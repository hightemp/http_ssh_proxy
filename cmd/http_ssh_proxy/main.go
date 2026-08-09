package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("[STARTUP] Reading config file %s", *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Error loading config: %v", err)
	}
	if *checkConfig {
		fmt.Printf("configuration valid: %s\n", *configPath)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg); err != nil {
		log.Fatalf("[FATAL] Proxy stopped with an error: %v", err)
	}
}
