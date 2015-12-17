AMFS_VERSION="0.1"

EXTRA_CFLAGS += -DAMFS_VERSION=\"$(AMFS_VERSION)\"

obj-$(CONFIG_AM_FS) += amfs.o

amfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

all: amfsctl amfs

amfsctl: amfsctl.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi amfsctl.c -o amfsctl

amfs:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f amfsctl
