package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ProxyAddr       string `yaml:"ProxyAddr"`
	SshAddr         string `yaml:"SshAddr"`
	SshUser         string `yaml:"SshUser"`
	SshPassword     string `yaml:"SshPassword"`
	SshIdentityFile string `yaml:"SshIdentityFile"`
}

var (
	config Config
)

func LoadConfig(path string) error {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading YAML file: %v", err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return fmt.Errorf("error parsing YAML file: %v", err)
	}

	return nil
}

func loadPrivateKey(filePath string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}

func main() {
	argConfigPath := flag.String("config", "./config.yaml", "Config file path")

	err := LoadConfig(*argConfigPath)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	var sshConfig *ssh.ClientConfig

	if config.SshPassword != "" {
		sshConfig = &ssh.ClientConfig{
			User: config.SshUser,
			Auth: []ssh.AuthMethod{
				ssh.Password(config.SshPassword),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else if config.SshIdentityFile != "" {
		authMethod, err := loadPrivateKey(config.SshIdentityFile)
		if err != nil {
			log.Fatalf("Failed to load private key: %s", err)
		}

		sshConfig = &ssh.ClientConfig{
			User: config.SshUser,
			Auth: []ssh.AuthMethod{
				authMethod,
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else {
		log.Fatal("auth option required")
	}

	sshClient, err := ssh.Dial("tcp", config.SshAddr, sshConfig)
	if err != nil {
		log.Fatalf("Failed to dial SSH server: %v", err)
	}
	defer sshClient.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(w, r, sshClient)
		} else {
			handleHTTP(w, r, sshClient)
		}
	})

	fmt.Printf("Starting proxy server on %s\n", config.ProxyAddr)
	log.Fatal(http.ListenAndServe(config.ProxyAddr, nil))
}

func handleTunneling(w http.ResponseWriter, r *http.Request, sshClient *ssh.Client) {
	destConn, err := sshClient.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, sshClient *ssh.Client) {
	resp, err := forwardRequest(r, sshClient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func forwardRequest(r *http.Request, sshClient *ssh.Client) (*http.Response, error) {
	transport := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return sshClient.Dial(network, addr)
		},
	}
	client := &http.Client{Transport: transport}
	return client.Do(r)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
