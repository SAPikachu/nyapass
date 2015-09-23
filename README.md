# nyapass
Hidden HTTP proxy

## Why?
Ask Mr. Fang please.

## Features
* Standard non-caching HTTP proxy with CONNECT support.
* Run as standalone proxy, or delegate requests to another HTTP proxy (like polipo or squid)
* Communication is done in HTTPS, making it hard to detect.
* Act as an innocent HTTPS website to unauthorized clients.
* Integrated chnroutes support.

## System requirement
* Python 3.4+
* Tested on Ubuntu 15.04, should work on most Linux/FreeBSD systems that are reasonably updated

## Quick start (Server)
1. Ensure version of Python is at least 3.4:
    ```
    $ python3 -V
    Python 3.4.3
  	```

2. Clone this repo:
	  ```
    git clone https://github.com/SAPikachu/nyapass.git
    cd nyapass
    ```

3. Install required packages:
  	```
    pip3 install -r requirements.txt
    ```

4. Prepare a TLS server certificate. It is recommended to use proper certificate that is signed by browser-trusted CAs, to reduce chance of being detected. For testing or quick usage, we can also use a [self-signed certificate](https://devcenter.heroku.com/articles/ssl-certificate-self).

	  By default, `nyapass` reads certificate from `nyapass-server.crt` and private key from `nyapass-server.key`. You may use different file names, but you will have to change related entries in `config.json` (described later).

5. Copy `config.json.example` to `config.json`, and edit it.

    Things you *need* to edit:
    
    * `password`: For obvious reason.
    * `server.masq_host`: Set this to domain of an HTTP website, which will be returned to unauthorized clients. Sites with a lot of big files (like gitweb of popular open source project) is suggested.

(To be continued...)
