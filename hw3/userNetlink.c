#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "sys_submitjob.h"

#define SIZE_OF_PAYLOAD_ALLOWED 1024

struct sockaddr_nl source_address;
struct nlmsghdr *netlink_header = NULL;
struct iovec iov;
int socket_file_descriptor;
struct msghdr message;


int netlink_callback(void)
{
	int ret = 0, process_id;
	socket_file_descriptor = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
	if (socket_file_descriptor < 0) {
		printf("Socket File Error: %d\n", socket_file_descriptor);
		ret = -1;
		goto out;
	}

	process_id = getpid();
	memset(&source_address, 0, sizeof(&source_address));

	source_address.nl_family = AF_NETLINK;
	source_address.nl_pid = process_id;

	bind(socket_file_descriptor, (struct sockaddr *)&source_address, sizeof(source_address));

	netlink_header = (struct nlmsghdr *)(malloc(NLMSG_SPACE(SIZE_OF_PAYLOAD_ALLOWED)));

	memset(netlink_header, 0, NLMSG_SPACE(SIZE_OF_PAYLOAD_ALLOWED));

	netlink_header->nlmsg_len = NLMSG_SPACE(SIZE_OF_PAYLOAD_ALLOWED);
	netlink_header->nlmsg_pid = process_id;
	netlink_header->nlmsg_flags = 0;

	iov.iov_base = (void *) netlink_header;
	iov.iov_len = netlink_header->nlmsg_len;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;


	recvmsg(socket_file_descriptor, &message, 0);
	printf("JOB STATUS: \n");
	printf("%s\n ", (char *)NLMSG_DATA(netlink_header));
	close(socket_file_descriptor);

out:
	return ret;

}
