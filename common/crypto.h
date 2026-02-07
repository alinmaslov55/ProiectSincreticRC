#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>

void init_openssl();
void cleanup_openssl();
SSL_CTX *create_context(bool is_server);
void configure_server_context(SSL_CTX *ctx);

#endif