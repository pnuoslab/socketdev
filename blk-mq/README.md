# Usage

## Build

If you want logging, set the "BLKDEV_DEBUG" macro to 1 (line 18 of blkdev.c)

```bash
$ make
```

## Install

Install blkdev module
Arguments
 - servaddr: server address
 - servport: server port
 - name: device name
 - sz: device capacity

```bash
# insmod blk-mq/blkdev.ko servaddr="x.x.x.x" servport=4444 name="mysocketdev" sz="10G"
```
