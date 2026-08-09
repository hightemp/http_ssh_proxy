package sshmanager

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/hightemp/http_ssh_proxy/internal/config"

	"golang.org/x/crypto/ssh"
)

func isDestinationDialError(err error) bool {
	var openChannelErr *ssh.OpenChannelError
	return errors.As(err, &openChannelErr)
}

func dialSSH(cfg *config.Config) (*ssh.Client, error) {
	var auth []ssh.AuthMethod
	if cfg.SSHPassword != "" {
		auth = append(auth, ssh.Password(cfg.SSHPassword))
	}
	if cfg.SSHKeyFile != "" {
		key, err := os.ReadFile(cfg.SSHKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read SSH key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", cfg.SSHHost, cfg.SSHPort), sshConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}
