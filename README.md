# HeartBleed

The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. This weakness allows stealing the information protected, under normal conditions, by the SSL/TLS encryption used to secure the Internet. SSL/TLS provides communication security and privacy over the Internet for applications such as web, email, instant messaging (IM) and some virtual private networks (VPNs).
The Heartbleed bug allows anyone on the Internet to read the memory of the systems protected by the vulnerable versions of the OpenSSL software. This compromises the secret keys used to identify the service providers and to encrypt the traffic, the names and passwords of the users and the actual content. This allows attackers to eavesdrop on communications, steal data directly from the services and users and to impersonate services and users.

## Setup

### Vulnerable Server Setup

1. [Install Ubuntu 11.04](http://old-releases.ubuntu.com/releases/11.04/)
2. [Download openssl-1.0.1a.tar.gz](https://ftp.openssl.org/source/old/1.0.1/)
3. Extact tar archive and run the following commands:
```
./config
make
make test
sudo make install
sudo mv /usr/bin/openssl /root/
sudo ln -s /usr/local/ssl/bin/openssl /usr/bin/openssl
```
4. Run an HTTPS server
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -key key.pem -cert cert.pem -accept 44330 -www
```

Now you have a running HTTPS server on port 44330.
