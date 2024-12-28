package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ProxyAddr   string `yaml:"listen_addr"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	Proto       string `yaml:"proto"`
	CertPath    string `yaml:"pem_path"`
	KeyPath     string `yaml:"key_path"`
	SSHHost     string `yaml:"ssh_host"`
	SSHPort     int    `yaml:"ssh_port"`
	SSHUser     string `yaml:"ssh_user"`
	SSHPassword string `yaml:"ssh_pass"`
	SSHKeyFile  string `yaml:"ssh_key_file"`
}

var config Config
var sshClient *ssh.Client

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the config file")
	flag.Parse()

	log.Printf("Trying to read config file %s\n", *configPath)

	content, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	err = yaml.Unmarshal(content, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	sshClient, err = setupSSHClient()
	if err != nil {
		log.Fatalf("Error setting up SSH client: %v", err)
	}
	defer sshClient.Close()

	server := &http.Server{
		Addr: config.ProxyAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println("Received request:", r.Method, r.URL)
			if config.Username != "" && !basicAuth(w, r) {
				return
			}
			handleTunneling(w, r)
		}),
		TLSConfig: &tls.Config{},
	}

	log.Printf("Starting proxy server on %s\n", config.ProxyAddr)
	if config.Proto == "https" {
		cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
		if err != nil {
			log.Fatalf("Error loading TLS certificate: %v", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		listener, err := tls.Listen("tcp", config.ProxyAddr, tlsConfig)
		if err != nil {
			log.Fatalf("Error creating TLS listener: %v", err)
		}
		defer listener.Close()

		log.Fatal(server.Serve(listener))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func setupSSHClient() (*ssh.Client, error) {
	var auth []ssh.AuthMethod
	if config.SSHPassword != "" {
		auth = append(auth, ssh.Password(config.SSHPassword))
	}
	if config.SSHKeyFile != "" {
		key, err := os.ReadFile(config.SSHKeyFile)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	sshConfig := &ssh.ClientConfig{
		User:            config.SSHUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.SSHHost, config.SSHPort), sshConfig)
}

func basicAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		log.Println("No Proxy-Authorization header")
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		log.Println("Error decoding auth:", err)
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		log.Printf("Invalid auth format: %v\n", pair)
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	if pair[0] != config.Username || pair[1] != config.Password {
		log.Printf("Invalid credentials: %s:%s\n", pair[0], pair[1])
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Authorization Required"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return false
	}

	return true
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		log.Printf("Error: Method not allowed: %s\n", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	destConn, err := sshClient.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("Error: Can't connect to host through SSH tunnel: %s, %v\n", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Error: Hijacking not supported\n")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Error: Client connection error: %v\n", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	bytes, err := io.Copy(destination, source)
	if err != nil {
		if err, ok := err.(*ssh.ExitError); ok {
			log.Printf("SSH exit error: %v\n", err)
		} else {
			log.Printf("Transfer error: %v\n", err)
		}
	} else {
		log.Printf("Transferred %d bytes\n", bytes)
	}
}
