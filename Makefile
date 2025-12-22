CC=gcc
CFLAGS=-Wall -pthread -Iinclude

all: server client

server:
	$(CC) $(CFLAGS) server/vault_server.c libproto/protocol.c -o vault_server

client:
	$(CC) $(CFLAGS) client/vault_client.c libproto/protocol.c -o vault_client

clean:
	rm -f vault_server vault_client
