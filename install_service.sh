#!/bin/bash

SERVICE_NAME="http_ssh_proxy"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
CONFIG_FILE="/etc/$SERVICE_NAME/config.yaml"
BINARY_PATH="/usr/local/bin/$SERVICE_NAME"

sudo systemctl stop $SERVICE_NAME

sudo mkdir -p /etc/$SERVICE_NAME

sudo cp config.yaml $CONFIG_FILE
sudo chown $USER:$USER $CONFIG_FILE

cat <<EOL > $SERVICE_FILE
[Unit]
Description=HTTP SSH Proxy Service
After=network.target

[Service]
Type=$USER
User=$USER
ExecStart=$BINARY_PATH
Restart=always
Environment=CONFIG_PATH=$CONFIG_FILE

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload

systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo "Service $SERVICE_NAME installed and started."

systemctl status $SERVICE_NAME
