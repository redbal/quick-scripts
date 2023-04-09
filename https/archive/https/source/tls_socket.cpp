#include <iostream>
#include <vector>
#include <cerrno>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls_socket.h"
#include "http.h"

using namespace Dropper;
char buff[512] {0};
int ret {0};

const char *USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) "
                         "AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/65.0.3325.181 Safari/537.36";

const char *url = "https://localhost:8443/index.php";

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
        inet_ntop(AF_INET, &m_servAddr.sin_addr, buff, sizeof( buff ));
        std::cout << "ERROR: "<< host << " invalid address: " << buff << std::endl;
    }

    if ((ret = ::connect(m_sockfd, (struct sockaddr*) &m_servAddr, sizeof(m_servAddr)))
        != 0) {
        std::cout << "ERROR: failed to connect" << std::endl;
    }
    else { std::cout << "Socket connected m_sockfd: " << m_sockfd << std::endl; }
}

void TLS_Socket::tls_connect()
{
    std::cout << "tls_connect " << m_ctx << std::endl;
    SSL_CTX_set_security_level(m_ctx, 0);
    m_ssl = SSL_new(m_ctx);
    std::cout << "Setting socket fd " << m_sockfd << " to ssl object" << std::endl;
    SSL_set_fd(m_ssl, m_sockfd);
    
    int ret, res;
    ret = SSL_connect(m_ssl);
    res = SSL_get_error(m_ssl, ret);
    if ( res != 1) { std::cout << "SSL_connect get_error: [" << res << "]" << std::endl; }
}

void TLS_Socket::send()
{
    char buf[256];
    std::cout << "send " << m_ssl << std::endl;
    HttpRequest request = HttpRequest(url);    
    request.customHeaders.push_back(HttpHeader("User-Agent", USER_AGENT));
    std::string requestStr = request.generate();
    std::cout << "requestStr: " << std::endl << requestStr << std::endl;

    //SSL_write(ssl, buf, strlen(buf) + 1);
    //len = SSL_read(ssl, buf, sizeof(buf));
    //std::cout << "msg length: " << msg.length() << " strlen: " << strlen(msg.data()) << std::endl;

    if ( (ret = SSL_write(m_ssl, requestStr.c_str(), requestStr.length())) != 1) {
        int res = SSL_get_error(m_ssl, ret);
        printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
        //std::cout << "SSL_write get_error: " << res <<  std::endl << std::strerror(errno) << std::endl; 
    }
}

void TLS_Socket::recv()
{
    std::cout << "recv " << m_ctx << std::endl;
    HttpResponse response = HttpResponse();
    HttpReader *httpReader = HttpReaderNew(response);
    
    char readbuf[8192];
    size_t readlen;
    std::vector<std::string> vect;
    while ((readlen = SSL_read(m_ssl, readbuf, sizeof(readbuf) - 1)) > 0) {
      std::cout<< ".";
      readbuf[readlen] = 0;
      vect.push_back(readbuf);
      httpReader->onBuffer(readbuf, readlen, sizeof(readbuf));
      if (httpReader->isFinished())
        break;
    }
    delete httpReader;

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
    std::cout << "set_tls_version " << tls_version << std::endl;
    const SSL_METHOD* method = TLSv1_2_client_method(); 
    m_ctx = SSL_CTX_new(method);
}

void TLS_Socket::set_tls_ciphers(const char* tls_ciphers)
{
    std::cout << "set_tls_cipher " << tls_ciphers << std::endl;
    SSL_CTX_set_cipher_list(m_ctx, tls_ciphers);
}

void TLS_Socket::set_tls_cert(const char* cert_path)
{
}

void TLS_Socket::set_tls_cert_buff(std::vector<char> cert_buff)
{
    std::cout << "set_tls_cert_buff size: " << cert_buff.size() << std::endl;
    SSL_CTX_use_certificate_file(m_ctx, cert_buff.data(), SSL_FILETYPE_PEM);
}

void TLS_Socket::set_tls_extensions(const char* extensions) 
{
    std::cout << "set_tls_extensions" << extensions << std::endl;
    /*
     int SSL_CTX_add_client_custom_ext(SSL_CTX *ctx, 
                                   unsigned int ext_type,
                                   custom_ext_add_cb add_cb,
                                   custom_ext_free_cb free_cb, 
                                   void *add_arg,
                                   custom_ext_parse_cb parse_cb,
                                   void *parse_arg);

    if (!SSL_CTX_add_client_custom_ext(m_ctx, 
                                       TLSEXT_TYPE_supported_versions, 
                                       0, 
                                       0,
                                       nullptr, 
                                       0, 
                                       nullptr)) {
        std::cout << "Unable to add client custom extension" << std::endl;
    }
    */
}

void TLS_Socket::set_tls_curves(std::vector<uint8_t> curves)
{}

void TLS_Socket::set_tls_curve_formats(std::vector<uint8_t> curve_format)
{}
