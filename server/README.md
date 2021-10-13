# Usage

## Build

Setting the server IP address and port for testing clinet (line 16 and 20 of usocket_cli.c)

Setting the port for server (line 26 of usocket_srv.c)

If you want logging, set the "SERV_DEBUG" macro to 1 (line 21 of usocket_srv.c)

If you use with FTL, set the "ALLOW_FTL" macro to 1 (line 12 of usocket_srv.c)

```bash
$ make
```

## Run

### Using file

Create a file as a storage

```bash
$ truncate -s 10G ./myfile
```

Change the file path in line 142 of usocket_srv.c
(e.g., fd = open("./myfile", O_RDWR);)

Run the Server
```bash
$ ./usocket_srv
```

Run the Client for socket testing

```bash
# ./usocket_cli
```
