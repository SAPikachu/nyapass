#!/bin/bash

# Most of the code is stolen from Docker installation script


command_exists() {
    command -v "$@" > /dev/null 2>&1
}

main() {
    set -eu
    if command_exists curl; then
        curl='curl -sSL'
    elif command_exists wget; then
        curl='wget -qO-'
    elif command_exists busybox && busybox --list-modules | grep -q wget; then
        curl='busybox wget -qO-'
    else
        apt-get update
        apt-get install -y curl
        curl='curl -sSL'
    fi

    if [ ! -f config.json ]; then
        echo "Can't find config.json, generating one."
        while true; do
            IFS='' read -r -p "Enter masquerading target (empty to use www.apple.com, which is only recommended for testing): " MASQ
            if [ -z "$MASQ" ]; then
                MASQ="www.apple.com"
            fi
            echo "Checking whether $MASQ is reachable..."
            $curl "http://$MASQ" >/dev/null 2>&1 || {
                echo "Error: $MASQ is not reachable"
                continue
            }
            break
        done
        IFS='' read -r -p "Enter your password (please don't enter special characters here, if you need that, please create config.json manually), or press enter to generate a random one: " PASSWORD
        if [ -z "$PASSWORD" ]; then
            PASSWORD=$(dd if=/dev/urandom bs=24 count=1 2>/dev/null | xxd -p)
        fi
        echo Your password is: \"$PASSWORD\" \(without quotes\)
        echo Press enter to clear terminal and continue.
        read -s dummy
        clear || true
        $curl https://raw.githubusercontent.com/SAPikachu/nyapass/master/config.json.example > config.json
        sed -i "s/\"password\": *\"[^\"]*\"/\"password\": \"$PASSWORD\"/g" config.json
        sed -i "s/\"masq_host\": *\"[^\"]*\"/\"masq_host\": \"$MASQ\"/g" config.json
    fi
    if [ ! -f nyapass-server.crt ]; then
        echo "Can't find nyapass-server.crt, generating a self-signed certificate."
        if ! command_exists openssl; then
            apt-get update
            apt-get install -y openssl
        fi
        openssl genrsa -des3 -passout pass:x -out nyapass-server.pass.key 2048
        openssl rsa -passin pass:x -in nyapass-server.pass.key -out nyapass-server.key
        rm nyapass-server.pass.key
        echo Please enter information for your certificate, or just keep pressing enter to accept all defaults.
        openssl req -new -key nyapass-server.key -out nyapass-server.csr
        openssl x509 -req -days 3650 -in nyapass-server.csr -signkey nyapass-server.key -out nyapass-server.crt
        rm nyapass-server.csr
    fi
    if [ ! -f nyapass-server.key ]; then
        echo "Error: Can't find nyapass-server.key"
        exit 1
    fi
    if ! command_exists docker; then
        echo Installing docker...
        $curl https://get.docker.com/ | sh
        {
            docker info || start docker || systemctl start docker
        } >/dev/null 2>&1
    fi
    echo Building Docker image...
    INSTDIR=/tmp/nyapass-server-docker
    [ ! -d $INSTDIR ] || rm -r $INSTDIR
    mkdir -p $INSTDIR
    cp config.json nyapass-server.{crt,key} $INSTDIR/
    cd $INSTDIR
    $curl https://raw.githubusercontent.com/SAPikachu/nyapass/master/docker/server/Dockerfile > Dockerfile
    docker build --no-cache -t nyapass-server .

    echo Creating container...
    docker rm -f nyapass-server >/dev/null 2>&1 || true
    docker run -d --restart=always --name nyapass-server -p 0.0.0.0:443:443 nyapass-server
    cd /
    rm -r $INSTDIR
    echo Installation completed.
    exit 0
}

if [ "${1:-}" == "--auto" ]; then
    {
        set -eu
        while true; do echo "" 2>/dev/null || break; done
    } | main
else
    main
fi
