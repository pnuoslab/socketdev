#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <signal.h>
#include <pthread.h>

#define ALLOW_FTL	1

#if ALLOW_FTL
#include "module.h"
#include "flash.h"
#include "page.h"
#include "device.h"
#endif

#define SERV_DEBUG	1

typedef unsigned long long u64;
typedef unsigned short u16;

#define PORT		4444
#define INIT		-1
#define READ		0
#define WRITE		1

typedef struct {
	unsigned int op;
	loff_t offset;
	u64 size;
	u16 tag;
} packet_t;

int ncores;
int server_fd;
struct sockaddr_in addr_srv;
int addr_len = sizeof(addr_srv);

#if ALLOW_FTL
struct flash_device *flash;
#endif

int recv_packet(int client_fd, packet_t *packet)
{
	int len;

	len = recv(client_fd, packet, sizeof(packet_t), MSG_WAITALL);
  if (len != sizeof(packet_t)) {
		perror("recv packet failed");
  }

#if SERV_DEBUG
	printf("recv packet op(%d) offset(%lu) size(%llu) tag(%u)\n",
			packet->op, packet->offset, packet->size, packet->tag);
#endif

	return len;
}

int write_data(int client_fd, int fd, packet_t *packet, char *buffer)
{
	int len;

	len = recv(client_fd, buffer, packet->size, MSG_WAITALL);
	if (len != packet->size) {
		perror("recv failed");
		return len;
	}

#if SERV_DEBUG
	printf("write: offset(%ld) size(%llu)\n", packet->offset, packet->size);
#endif

#if ALLOW_FTL
	if (flash->f_op->write(flash, buffer, packet->size, packet->offset) != (ssize_t)packet->size)
		perror("write failed");
#else
	if (pwrite(fd, buffer, packet->size, packet->offset) != (ssize_t)packet->size)
		perror("write failed");
#endif
	len = send(client_fd, packet, sizeof(packet_t), MSG_EOR);
	if (len != sizeof(packet_t))
		perror("send failed");

	return len;
}

int read_data(int client_fd, int fd, packet_t *packet, char *buffer)
{
	u64 len;
#if ALLOW_FTL
	if (flash->f_op->read(flash, buffer, packet->size, packet->offset) != (ssize_t)packet->size)
		perror("read failed");
#else
	if (pread(fd, buffer, packet->size, packet->offset) != (ssize_t)packet->size)
		perror("read failed");
#endif

#if SERV_DEBUG
	printf("read: offset(%ld) size(%llu)\n", packet->offset, packet->size);
#endif

	len = send(client_fd, packet, sizeof(packet_t), MSG_MORE);
	if (len != sizeof(packet_t)) {
		perror("send failed");
		return len;
	}

	len = send(client_fd, buffer, packet->size, MSG_EOR);
	if (len != packet->size)
		perror("send failed");

	return len;
}

void send_serv_cores(int client_fd)
{
	if (send(client_fd, &ncores, sizeof(int), MSG_EOR) != sizeof(int)) {
		perror("can't initialized");
		return;
	}

	printf("Connected.\n");
}

void *handle_packet(void *data)
{
	int client_fd = *((int *)(&data));
	int fd;
	packet_t packet;
	char *buffer;

	buffer = aligned_alloc(512, 2 * 1024 * 1024);
	if (!buffer) {
		perror("no memory");
		goto out;
	}

	fd = open("data_file", O_CREAT | O_RDWR);
	if (fd < 0) {
		perror("open error");
		free(buffer);
		goto out;
	}

	while (1) {
		if (recv_packet(client_fd, &packet) <= 0)
			break;

		switch (packet.op) {
			case INIT:
				send_serv_cores(client_fd);
				goto out;
			case READ:
				if (read_data(client_fd, fd, &packet, buffer) <= 0)
					goto out;
				break;
			case WRITE:
				if (write_data(client_fd, fd, &packet, buffer) <= 0)
					goto out;
			default:
				break;
		}
	}
	close(fd);
out:
	close(client_fd);

	return NULL;
}

void run_server()
{
	pthread_t thread;
	int tid;
	long client_fd;

	while (1) {
		if ((client_fd = accept(server_fd, (struct sockaddr *)&addr_srv,
						(socklen_t *)&addr_len)) < 0) {
			perror("accept failed");
		} else { 
			tid = pthread_create(&thread, NULL, handle_packet, (void *)client_fd);
			if (tid < 0) {
				perror("fail to create thread");
				close(client_fd);
			}
		}
	}
}

void init_server()
{
	int opt;

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
				&opt, sizeof(opt))) {
		perror("set socket failed");
		exit(EXIT_FAILURE);
	}

	addr_srv.sin_family = AF_INET;
	addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_srv.sin_port = htons(PORT);

	if (bind(server_fd, (struct sockaddr *)&addr_srv, sizeof(addr_srv))) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, ncores)) {
		perror("listen failed");
		exit(EXIT_FAILURE);
	}
}

void sigint_handler(int sig)
{
	sig = sig;

	if (server_fd > 0)
		close(server_fd);

#if ALLOW_FTL
	flash->f_op->close(flash);
	module_exit(flash);
#endif

	exit(0);
}

int main()
{
	signal(SIGINT, sigint_handler);

	ncores = get_nprocs();

#if ALLOW_FTL
	module_init(PAGE_FTL_MODULE, &flash, RAMDISK_MODULE);
	flash->f_op->open(flash, NULL, O_CREAT | O_RDWR);
#endif

	init_server();

	printf("cores: %d, port: %d\nserver listen...\n", ncores, PORT);

	run_server();

#if ALLOW_FTL
	flash->f_op->close(flash);
	module_exit(flash);
#endif

	return 0;
}
