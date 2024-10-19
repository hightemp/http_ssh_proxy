#!/bin/bash

# curl -Lv --proxy https://localhost:8888 --proxy-cacert server.pem https://google.com
# curl -Lv --proxy https://localhost:8888 --proxy-insecure https://google.com
curl -Lv --proxy http://localhost:8888 \
    --proxy-user "test:test" \
    https://google.com