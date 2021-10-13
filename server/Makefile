CC=gcc

LIBS = -lpthread

SERVER_OBJS=usocket_srv.o
CLIENT_OBJS=usocket_cli.o

SERVER_TARGET=usocket_srv
CLIENT_TARGET=usocket_cli

all: server client

server: $(SERVER_OBJS)
	$(CC) -o $(SERVER_TARGET) $(SERVER_OBJS) $(LIBS)

client: $(CLIENT_OBJS)
	$(CC) -o $(CLIENT_TARGET) $(CLIENT_OBJS)

clean:
	rm -rf $(SERVER_TARGET) $(CLIENT_TARGET) $(SERVER_OBJS) $(CLIENT_OBJS)
