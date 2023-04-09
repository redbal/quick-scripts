#ifndef TLS_SOCKET_H
#define TLS_SOCKET_H

#include <tls.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats */

namespace Dropper{

    class TLS_Socket {
        private:
            SSL_CTX*       m_ctx;
            SSL*           m_ssl;
            int                m_sockfd;
            struct sockaddr_in m_servAddr;

        public:
            TLS_Socket();
            ~TLS_Socket();
            void create_socket();
            void connect(const char* host, int port);
            void ssl_connect();

            void set_tls_cert(const char* cert_path);
            void set_tls_version(const char* tls_version);
            void set_tls_ciphers(const char* tls_ciphers);
            void set_tls_host(const char* host);
            void set_tls_port(int port);
            void set_tls_extensions(std::vector<uint8_t> extensions);
            void set_tls_curves(std::vector<uint8_t> curves);
            void set_tls_curve_formats(std::vector<uint8_t> curve_format);
            void set_tls_cert_buff(std::vector<char> cert_buff);
            void send();
            void recv();
            void cleanup();
    };
}
#endif
