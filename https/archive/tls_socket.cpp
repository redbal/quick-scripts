#include <iostream>
#include <vector>
#include <openssl/ssl.h>
#include "tls_socket.h"


using namespace Dropper;
char buff[512] {0};
int ret {0};

TLS_Socket::TLS_Socket(){}
TLS_Socket::~TLS_Socket(){}

void TLS_Socket::create_socket() {
    if ((m_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        std::cout << "ERROR: failed to create the socket" << std::endl;
    }
}

void TLS_Socket::connect(const char* host, int port){
    m_servAddr.sin_family = AF_INET;
    m_servAddr.sin_port   = htons(port);

    if ((ret = inet_pton(AF_INET, host, &m_servAddr.sin_addr)) != 1) {
        inet_ntop( AF_INET, &m_servAddr.sin_addr, buff, sizeof( buff ));
        std::cout << "ERROR: invalid address: " << buff << std::endl;
    }

    if ((ret = ::connect(m_sockfd, (struct sockaddr*) &m_servAddr, sizeof(m_servAddr)))
        == -1) {
        std::cout << "ERROR: failed to connect" << std::endl;
    }

}

void TLS_Socket::ssl_connect()
{
    ret = tls_init();
    struct tls *tls {nullptr};
    struct tls_config *cfg {nullptr};
    
    if ((tls = tls_client()) == NULL){
        printf("BAD\n");
    } else { printf("GOOD\n");}

    if (tls_configure(tls, cfg) != 0) {
        printf("tls_configure: %s", tls_error(tls));
        exit(-5);
    } else { printf("GOOD tls_configure\n");}

  
   if (tls_connect(
          tls, "localhost", "8443") !=0) {
        printf("tls_connect: %s", tls_error(tls));
        exit(-6);
    } else { printf("GOOD tls_connect\n");}
    
    std::string msg = "TEST";
    if ((tls_write(tls, msg.c_str(), sizeof(msg))) < 0) {
        printf("tls_write: %s", tls_error(tls));
        exit(-7);
    } else { printf("GOOD tls_write\n");}

    char readbuf[1024];
    size_t readlen;
    while ((readlen = tls_read(tls, readbuf, sizeof(readbuf) - 1)) > 0) {
        std::cout << "Read " << readlen << " bytes" << std::endl;
        
    }
}

void TLS_Socket::send()
{
    memset(buff, 0, sizeof(buff));
    if (fgets(buff, sizeof(buff), stdin) == NULL) {
        std::cout << "ERROR: failed to get message for server" << std::endl;
    }
    int len = strnlen(buff, sizeof(buff));
    if ((ret = SSL_write(m_ssl, buff, len)) != len) {
        std::cout << "ERROR: failed to write entire message" << std::endl;
        std::cout << ret << " bytes of " << len << "bytes were sent" << std::endl;
    }
}

void TLS_Socket::recv()
{
    memset(buff, 0, sizeof(buff)); //zero-ize
    if ((ret = SSL_read(m_ssl, buff, sizeof(buff)-1)) == -1) {
        std::cout << "ERROR: failed to read" << std::endl;
    }

    std::cout << "Server: " << buff << std::endl;
}

void TLS_Socket::cleanup()
{

}

void TLS_Socket::set_tls_version(const char* tls_version)
{
}

void TLS_Socket::set_tls_ciphers(const char* tls_ciphers)
{
}

void TLS_Socket::set_tls_cert(const char* cert_path)
{
}

void TLS_Socket::set_tls_cert_buff(std::vector<char> cert_buff)
{
}

void TLS_Socket::set_tls_extensions(std::vector<uint8_t> extensions) 
{}

void TLS_Socket::set_tls_curves(std::vector<uint8_t> curves)
{}

void TLS_Socket::set_tls_curve_formats(std::vector<uint8_t> curve_format)
{}