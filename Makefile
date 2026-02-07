CC = gcc
CFLAGS = -Wall -Wextra -I.common -I/usr/local/opt/openssl/include
LDFLAGS = -L/usr/local/opt/openssl/lib -lssl -lcrypto -pthread

# Targets
all: server_bin client_bin

server_bin: server/main.c common/crypto.c server/db_manager.c
	$(CC) $(CFLAGS) $^ -o build/server $(LDFLAGS)

client_bin: client/main.c common/crypto.c
	$(CC) $(CFLAGS) $^ -o build/client $(LDFLAGS)

clean:
	rm -f build/server build/client
