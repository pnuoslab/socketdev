CC=gcc

LIBS = -lpthread -lftl $(shell pkg-config --libs glib-2.0)
CFLAGS = $(shell pkg-config --cflags glib-2.0) -I/usr/local/include/ftl

SERVER_OBJS=usocket_srv.o
CLIENT_OBJS=usocket_cli.o

SERVER_TARGET=usocket_srv
CLIENT_TARGET=usocket_cli

all: server client

server: $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $(SERVER_TARGET) $(SERVER_OBJS) $(LIBS)

client: $(CLIENT_OBJS)
	$(CC) -o $(CLIENT_TARGET) $(CLIENT_OBJS)

clean:
	rm -rf $(SERVER_TARGET) $(CLIENT_TARGET) $(SERVER_OBJS) $(CLIENT_OBJS)
