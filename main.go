package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	SSHHost    string `yaml:"ssh_host"`
	SSHPort    int    `yaml:"ssh_port"`
	SSHUser    string `yaml:"ssh_user"`
	SSHPass    string `yaml:"ssh_pass"`
	SSHKeyFile string `yaml:"ssh_key_file"`
	Proto      string `yaml:"proto"`
	PemPath    string `yaml:"pem_path"`
	KeyPath    string `yaml:"key_path"`
}

var sshClient *ssh.Client

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling CONNECT request to %s", r.Host)

	destConn, err := sshClient.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("Failed to dial destination over SSH: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	log.Printf("Successfully dialed destination %s over SSH", r.Host)

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Failed to hijack connection: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	log.Printf("Successfully hijacked connection")

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	log.Printf("Starting transfer from %v to %v", source, destination)
	n, err := io.Copy(destination, source)
	if err != nil {
		log.Printf("Transfer error: %v", err)
	} else {
		log.Printf("Transfer completed: %d bytes", n)
	}
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if !strings.Contains(host, ":") {
		if req.TLS == nil {
			host += ":80"
		} else {
			host += ":443"
		}
	}
	log.Printf("Handling HTTP request to %s", host)

	// Устанавливаем соединение через SSH туннель
	destConn, err := sshClient.Dial("tcp", host)
	if err != nil {
		log.Printf("Failed to dial destination over SSH: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Failed to hijack connection: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Printf("Successfully hijacked connection and established SSH tunnel to %s", req.Host)

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	log.Printf("Loaded config: %+v", config)
	return &config, nil
}

func createSSHClient(config *Config) (*ssh.Client, error) {
	var auth []ssh.AuthMethod
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
		log.Printf("Using SSH key authentication")
	}

	if config.SSHPass != "" {
		auth = append(auth, ssh.Password(config.SSHPass))
		log.Printf("Using SSH password authentication")
	}

	clientConfig := &ssh.ClientConfig{
		User:            config.SSHUser,
		Auth:            auth,
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := net.JoinHostPort(config.SSHHost, fmt.Sprintf("%d", config.SSHPort))
	client, err := ssh.Dial("tcp", addr, clientConfig)
	if err != nil {
		return nil, err
	}
	log.Printf("SSH client created to %s", addr)
	return client, nil
}

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	sshClient, err = createSSHClient(config)
	if err != nil {
		log.Fatalf("Failed to create SSH client: %v", err)
	}

	server := &http.Server{
		Addr: config.ListenAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Received request: %v %v", r.Method, r.URL)
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	log.Printf("Starting proxy server on %s", config.ListenAddr)
	if config.Proto == "https" {
		err = server.ListenAndServeTLS(config.PemPath, config.KeyPath)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
