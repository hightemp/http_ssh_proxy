package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Конфигурационная структура для YAML
type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	SSHHost    string `yaml:"ssh_host"`
	SSHPort    int    `yaml:"ssh_port"`
	SSHUser    string `yaml:"ssh_user"`
	SSHPass    string `yaml:"ssh_pass"`
	SSHKeyFile string `yaml:"ssh_key_file"`
}

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// SSHDialer wraps an ssh.Client and implements a net.Dialer
type SSHDialer struct {
	Client *ssh.Client
}

// Dial implements net.Dialer
func (d SSHDialer) Dial(network, addr string) (net.Conn, error) {
	return d.Client.Dial(network, addr)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func appendHostToXForwardHeader(header http.Header, host string) {
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

type proxy struct {
	dialer SSHDialer
}

func (p *proxy) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	log.Println(req.RemoteAddr, " ", req.Method, " ", req.URL)

	if req.Method == http.MethodConnect {
		handleTunneling(wr, req, p.dialer)
	} else {
		handleHTTP(wr, req, p.dialer)
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request, dialer SSHDialer) {
	destConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

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
	defer clientConn.Close()

	_, err = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		log.Printf("Failed to write to client: %v", err)
		return
	}

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Printf("Error while copying: %v", err)
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request, dialer SSHDialer) {
	client := &http.Client{}
	req := r.Clone(r.Context())
	req.RequestURI = ""

	delHopHeaders(req.Header)

	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		appendHostToXForwardHeader(req.Header, clientIP)
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		log.Fatal("ServeHTTP:", err)
	}
	defer resp.Body.Close()

	delHopHeaders(resp.Header)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	configFile := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	file, err := os.Open(*configFile)
	if err != nil {
		log.Fatalf("failed to open config file: %v", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		log.Fatalf("failed to parse config file: %v", err)
	}

	sshClientConfig := &ssh.ClientConfig{
		User:            config.SSHUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if config.SSHPass != "" {
		sshClientConfig.Auth = append(sshClientConfig.Auth, ssh.Password(config.SSHPass))
	} else if config.SSHKeyFile != "" {
		key, err := os.ReadFile(config.SSHKeyFile)
		if err != nil {
			log.Fatalf("Unable to read private key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Fatalf("Unable to parse private key: %v", err)
		}
		sshClientConfig.Auth = append(sshClientConfig.Auth, ssh.PublicKeys(signer))
	} else {
		log.Fatalf("No authentication method specified for SSH")
	}

	sshConn, err := ssh.Dial("tcp", net.JoinHostPort(config.SSHHost, strconv.Itoa(config.SSHPort)), sshClientConfig)
	if err != nil {
		log.Fatalf("Failed to dial SSH: %v", err)
	}

	dialer := SSHDialer{Client: sshConn}

	proxyHandler := &proxy{dialer: dialer}

	log.Println("Starting proxy server on", config.ListenAddr)
	if err := http.ListenAndServe(config.ListenAddr, proxyHandler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
