CC=gcc
obj-m+=blkdev.o

EXTRA_LDFLAGS := -I$(PWD)/../ksocket
KBUILD_EXTRA_SYMBOLS='$(PWD)/../ksocket/Module.symvers'

all: module

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
