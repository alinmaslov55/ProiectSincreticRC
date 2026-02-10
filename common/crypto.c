#include "crypto.h"

#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/**
 * Data types Used:
 * SSL_CTX (SSL Context) - Retine configuratia globala a conexiunii
 * (versiunea de tls suportata, locatia certificatelor in server)
 * 
 * SSL_METHOD - asigura ca programul isi indeplineste rolul corect (client/server)
 * si foloseste versiunea TLS dorita
 * 
 * SSL_FILETYPE_PEM - macro utilizat pentru ca sa se inteleaga formatul sub care este scrisa key-ul/certificatul (PEM in cazul nostru)
 * 
 * SSL_load_error_strings(): Incarca descrieri e erorilor pe intelesul uman
 * 
 * OpenSSL_add_ssl_algorithms(): Inregistreaza toate algoritmii de criptare AES, SHA-256
 * 
 * EVP_cleanup() - apelat la sfarsit pentru a elibera resursele alocate de OpenSSL
 */


void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context(bool is_server){
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = is_server ? TLS_server_method() : TLS_client_method();

    ctx = SSL_CTX_new(method);
    if(!ctx){
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_server_context(SSL_CTX *ctx){
    if(SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM) <= 0){ // returneaza 1 la succes
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}