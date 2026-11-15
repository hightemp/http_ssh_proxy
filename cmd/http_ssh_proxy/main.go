package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hightemp/http_ssh_proxy/internal/app"
	"github.com/hightemp/http_ssh_proxy/internal/buildinfo"
	"github.com/hightemp/http_ssh_proxy/internal/config"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the config file")
	checkConfig := flag.Bool("check-config", false, "Validate the config file and exit")
	showVersion := flag.Bool("version", false, "Print version metadata and exit")
	trustHostKey := flag.Bool("trust-host-key", false, "Show the SSH server host key, add it to ssh_known_hosts_file after confirmation, and exit")
	assumeYes := flag.Bool("yes", false, "With -trust-host-key, add the key without asking for confirmation")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[STARTUP] Reading config file %s", *configPath)
	var loadOptions []config.LoadOption
	if *trustHostKey {
		loadOptions = append(loadOptions, config.AllowMissingKnownHostsFile())
	}
	cfg, err := config.Load(*configPath, loadOptions...)
	if err != nil {
		log.Fatalf("[FATAL] Error loading config: %v", err)
	}
	if *checkConfig {
		fmt.Printf("configuration valid: %s\n", *configPath)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *trustHostKey {
		if err := app.TrustHostKey(ctx, cfg, os.Stdin, os.Stdout, *assumeYes); err != nil {
			stop()
			log.Fatalf("[FATAL] %v", err)
		}
		return
	}
	if err := app.Run(ctx, cfg); err != nil {
		log.Fatalf("[FATAL] Proxy stopped with an error: %v", err)
	}
}
