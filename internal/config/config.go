// Package config defines the application configuration.
package config

// Config contains the proxy, TLS, and SSH settings.
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
