#define NETLINK_USER 31

#define ENCRYPTION  1
#define DECRYPTION  2
#define COMPRESS    3
#define DECOMPRESS  4
#define CHECKSUM    5
#define LIST        6
#define REMOVE      7
#define REMOVE_ALL	8
#define PRIORITY_CHANGE 9

#define MD5_ALGO 1
#define SHA_ALGO 2

#define MD5_DIGEST_LENGTH 16

int netlink_callback(void);

typedef struct job {
	int job_id;
	int jobtype;
	int algoType;
	pid_t pid;
	char *cipher;
	int cipher_len;
	int priority;
	char *infile;
	char *outfile;
} jobs;
