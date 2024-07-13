package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
}

var (
	configFile string
	config     Config
)

func init() {
	flag.StringVar(&configFile, "config", "config.yaml", "Path to config file")
	flag.Parse()
}

func main() {
	// Загрузка конфигурации
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	// Настройка SSH-клиента
	sshConfig := &ssh.ClientConfig{
		User:            config.SSHUser,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	if config.SSHPass != "" {
		sshConfig.Auth = append(sshConfig.Auth, ssh.Password(config.SSHPass))
	}

	if config.SSHKeyFile != "" {
		key, err := os.ReadFile(config.SSHKeyFile)
		if err != nil {
			log.Fatalf("Error reading SSH key file: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Fatalf("Error parsing SSH key: %v", err)
		}
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
	}

	// Настройка HTTP-прокси
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s", r.Method, r.URL)
		if r.Method == http.MethodConnect {
			handleTunneling(w, r, sshConfig)
		} else {
			handleHTTP(w, r, sshConfig)
		}
	})

	log.Printf("Starting proxy server on %s", config.ListenAddr)
	log.Fatal(http.ListenAndServe(config.ListenAddr, nil))
}

func handleTunneling(w http.ResponseWriter, r *http.Request, sshConfig *ssh.ClientConfig) {
	log.Printf("Handling CONNECT request for: %s", r.Host)

	destConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.SSHHost, config.SSHPort), sshConfig)
	if err != nil {
		log.Printf("Error connecting to SSH server: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	targetConn, err := destConn.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("Error dialing target host through SSH: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Error hijacking connection: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	log.Printf("Connection established, sending 200 OK")
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	log.Printf("Starting to transfer data for: %s", r.Host)
	go transfer(targetConn, clientConn)
	transfer(clientConn, targetConn)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, sshConfig *ssh.ClientConfig) {
	log.Printf("Handling HTTP request for: %s", r.URL)
	destConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.SSHHost, config.SSHPort), sshConfig)
	if err != nil {
		log.Printf("Error connecting to SSH server: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	targetConn, err := destConn.Dial("tcp", r.Host)
	if err != nil {
		log.Printf("Error dialing target host through SSH: %v", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	r.RequestURI = ""
	if err := r.Write(targetConn); err != nil {
		log.Printf("Error writing request to target: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(targetConn), r)
	if err != nil {
		log.Printf("Error reading response from target: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
