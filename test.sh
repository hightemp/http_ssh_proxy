#!/bin/bash

CONFIG_FILE="config.yaml"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Error: Config file $CONFIG_FILE not found"
  exit 1
fi

PORT=$(yq e '.listen_addr' $CONFIG_FILE | cut -d':' -f2)
CERT=$(yq e '.pem_path' $CONFIG_FILE)
USERNAME=$(yq e '.username' $CONFIG_FILE)
PASSWORD=$(yq e '.password' $CONFIG_FILE)

if [[ -z "$PORT" ]]; then
  echo "Error: Port not found in config"
  exit 1
fi

if [[ -z "$CERT" ]]; then
  echo "Error: Certificate path not found in config"
  exit 1
fi

show_menu() {
  echo "Select test case:"
  echo "1. HTTPS proxy with certificate verification"
  echo "2. HTTPS proxy with insecure flag"
  echo "3. HTTP proxy with basic authentication"
  echo "4. Exit"
}

run_test() {
  case $1 in
    1)
      echo "Running HTTPS proxy with certificate verification..."
      curl -Lv --proxy https://localhost:$PORT --proxy-cacert $CERT https://google.com
      ;;
    2)  
      echo "Running HTTPS proxy with insecure flag..."
      curl -Lv --proxy https://localhost:$PORT --proxy-insecure https://google.com
      ;;
    3)
      if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
        echo "Error: Username and password not configured"
        return
      fi
      echo "Running HTTP proxy with basic authentication..."
      curl -Lv --proxy http://localhost:$PORT --proxy-user "$USERNAME:$PASSWORD" https://google.com
      ;;
    4)
      echo "Exiting..."
      exit 0
      ;;
    *)
      echo "Invalid option"
      ;;
  esac
}

while true; do
  show_menu
  read -p "Enter your choice (1-4): " choice
  run_test $choice
  echo
done
