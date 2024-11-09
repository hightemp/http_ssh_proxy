#!/bin/bash

SERVICE_NAME="http_ssh_proxy"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
CONFIG_FILE="/etc/$SERVICE_NAME/config.yaml"
BINARY_PATH="/usr/local/bin/$SERVICE_NAME"

if [ ! -f "config.yaml" ]; then
    echo "Error: config.yaml not found"
    exit 1
fi

sudo systemctl stop $SERVICE_NAME

sudo mkdir -p /etc/$SERVICE_NAME

U=$USER

sudo cp $SERVICE_NAME $BINARY_PATH

sudo cp config.yaml $CONFIG_FILE
sudo chown $U:$U $CONFIG_FILE

sudo bash -c "cat <<EOL > $SERVICE_FILE
[Unit]
Description=HTTP SSH Proxy Service
After=network.target

[Service]
Type=simple
User=$U
Group=$U
ExecStart=$BINARY_PATH -config $CONFIG_FILE
Restart=always

[Install]
WantedBy=multi-user.target
EOL"

sudo systemctl daemon-reload

sudo systemctl enable $SERVICE_NAME

sudo chown $U:$U $SERVICE_FILE
sudo chmod a+x $SERVICE_FILE

ls -laht $SERVICE_FILE

sudo systemctl start $SERVICE_NAME

echo "Service $SERVICE_NAME installed and started."

sudo systemctl status $SERVICE_NAME
