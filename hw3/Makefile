obj-m += sys_submitjob.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: submitjob producer 

producer: producer.c userNetlink.o
	gcc -c userNetlink.c -o userNetlink.o
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi producer.c userNetlink.o -o producer -lssl -lcrypto -lpthread

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f producer	
	rm -f userNetlink.o
