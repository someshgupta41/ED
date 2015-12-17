#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stddef.h>
#include <openssl/md5.h>
#include <limits.h>
#include <pthread.h>
#include "sys_submitjob.h"

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif

extern int errno;

typedef struct command_args {
	int isEncrypt;
	int isDecrypt;
	int isCompress;
	int isDecompress;
	int isCheckSum;
	int isList;
	int isRemove;
	int isRemoveAll;
	int isPChange;
	int isPassword;
	unsigned char hash[MD5_DIGEST_LENGTH];
	int pwdLen;
	int isPriority;
	int priority;
	int jobtype;
	int isCallBack;
	int isAlgo;
	int algoType;
} sysargs;

pthread_t thread1, thread2, t_timer;


void displayMessage(char *string) 
{
	fprintf(stdout, "Usage : %s {-j ARG} [-p PASSWORD] [-c] [-o priority_number] [-a algo_number] [-h] inputFile outputFile \n", string);
	fprintf(stdout, "{-j 1} Use this option to specify whether you want to encrypt the inputfile\n");
	fprintf(stdout, "{-j 2} Use this option to specify whether you want to decrypt the inputfile\n");
	fprintf(stdout, "{-j 3} Use this option to specify whether you want to compress the inputfile\n");
	fprintf(stdout, "{-j 4} Use this option to specify whether you want to uncompress the inputfile\n");
	fprintf(stdout, "{-j 5} Use this option to specify whether you want to compute the checksum of the inputfile\n");
	fprintf(stdout, "{-j 6} Use this option to specify whether you want to list jobs\n");
	fprintf(stdout, "{-j 7} Use this option to specify whether you want to remove a job\n");
	fprintf(stdout, "{-j 8} Use this option to specify whether you want to remove all jobs\n");
	fprintf(stdout, "-p This option is used to specify the password. E.g. -p 'password123'\n");
	fprintf(stdout, "-o This option is used to specify priority number of the job.\n");
	fprintf(stdout, "-c This option is used to specify callback.\n");
	fprintf(stdout, "-a This option is used to specify algo. 1 for MD5 and 2 for SHA1.\n");
	fprintf(stdout, "-h Used to display the help message to outline the process on how to use the file\n");
	fprintf(stdout, "inputfile : specifies the inputfile to be encrypted/decrypted (with the path name)\n");
	fprintf(stdout, "outputfile : specifies the outputfile to be encrypted/decrypted (with the path name)\n");

}

void getFileName(char *file_name, char *file_output)
{
	char cwd[1024];

	if (strncmp(file_name, "/", 1) == 0) {
		strcpy(file_output, file_name);
	}
	else {
		if (getcwd(cwd, sizeof(cwd)) != NULL) {
			strcat(cwd, "/");
			strcat(cwd, file_name);
			strcpy(file_output, cwd);
		}
	}
}

int validate_and_parse_options(sysargs *sys, jobs *job, int argc, char **argv)
{
	int err = 0, isFiles = 0;
	int PAGE_SIZE = getpagesize ();

	switch (sys->jobtype) {
		case ENCRYPTION:
			
			if  ((argc != 9 && sys->isCallBack == 0) || (argc != 10 && sys->isCallBack == 1) || sys->isPassword == 0 || sys->isPriority == 0) {
				err = -EINVAL;
				goto out;
			}

			job->jobtype = ENCRYPTION;
			job->cipher =  (char *)sys->hash;
			job->cipher_len = MD5_DIGEST_LENGTH;
			isFiles = 1;			
			break;

		case DECRYPTION:
			
			if  ((argc != 9 && sys->isCallBack == 0) || (argc != 10 && sys->isCallBack == 1) || sys->isPassword == 0 || sys->isPriority == 0) {
				err = -EINVAL;
				goto out;
			}

			job->jobtype = DECRYPTION;
			job->cipher =  (char *)sys->hash;
			job->cipher_len = MD5_DIGEST_LENGTH;
			isFiles = 1;
			break;

		case COMPRESS:
			
			if  ((argc != 7 && sys->isCallBack == 0) || (argc != 8 && sys->isCallBack == 1) || sys->isPriority == 0) {
				err = -EINVAL;
				goto out;
			}

			job->jobtype = COMPRESS;
			isFiles = 1;
			break;

		case DECOMPRESS:
			
			if  ((argc != 7 && sys->isCallBack == 0) || (argc != 8 && sys->isCallBack == 1) || sys->isPriority == 0) {
				err = -EINVAL;
				goto out;
			}

			job->jobtype = DECOMPRESS;
			isFiles = 1;
			break;

		case CHECKSUM:
			
			if  ((argc != 9 && sys->isCallBack == 0) || (argc != 10 && sys->isCallBack == 1) || sys->isPriority == 0 || sys->isAlgo == 0) {
				printf ("Invalid checksum received!\n");
				err = -EINVAL;
				goto out;
			}

			
			job->jobtype = CHECKSUM;
			job->algoType = sys->algoType;
			isFiles = 1;
			break;

		case LIST:
			
			if  ((argc != 3 && sys->isCallBack == 0) || (argc != 4 && sys->isCallBack == 1)) {
				err = -EINVAL;
				goto out;
			}
			job->jobtype = LIST;
			job->outfile =  (char *) malloc(PAGE_SIZE);
			memset(job->outfile, 0, PAGE_SIZE);
			break;

		case REMOVE:
			
			if  ((argc != 4 && sys->isCallBack == 0) || (argc != 5 && sys->isCallBack == 1)) {
				err = -EINVAL;
				goto out;
			}

			if (atoi(argv[optind]) < 1 || atoi(argv[optind]) > INT_MAX) {
				err = -EINVAL;
				goto out;
			}

			job->job_id = atoi (argv[optind]);
			job->outfile =  (char *) malloc(PAGE_SIZE);
			memset(job->outfile, 0, PAGE_SIZE);
			job->jobtype = REMOVE;
			break;

		case REMOVE_ALL:
			
			if  ((argc != 3 && sys->isCallBack == 0) || (argc != 4 && sys->isCallBack == 1)) {
				err = -EINVAL;
				goto out;
			}
			job->jobtype = REMOVE_ALL;
			job->outfile =  (char *) malloc(PAGE_SIZE);
			memset(job->outfile, 0, PAGE_SIZE);
			break;

		case PRIORITY_CHANGE:
			
			if  ((argc != 6 && sys->isPriority == 0) || (argc != 6 && sys->isPChange == 1)) {
				err = -EINVAL;
				goto out;
			}

			if (atoi(argv[optind]) < 1 || atoi(argv[optind]) > INT_MAX) {
				err = -EINVAL;
				goto out;
			}

			job->job_id = atoi (argv[optind]);
			job->jobtype = PRIORITY_CHANGE;
			job->outfile =  (char *) malloc(PAGE_SIZE);
			memset(job->outfile, 0, PAGE_SIZE);
			break;

		default:
			err = -EINVAL;
			break;
	}

	if (isFiles == 1) {
		job->infile =  (char *) malloc(1024);
		getFileName (argv[optind], job->infile);		

		job->outfile =  (char *) malloc(1024);
		getFileName (argv[optind+1], job->outfile);		
	}

	job->pid = getpid();
	job->priority = sys->priority;

out:
	return err;

}

void displayCounter (void)
{
	int i;
	for (i = 0; i < 5; i++)
	{
		printf("Counter=> %d\n", i);
		sleep(1);
	}
}

void timer_thread()
{
    #define TIMEOUT 1*120
    int count = 0;
    while (TIMEOUT > count) {
        sleep(1);  //sleep for a secand
        count++;
    }    
    pthread_cancel(thread1); // cancel netlink thread

}

int main(int argc, char *argv[])
{
	int ch, ret = 0, err = 0;
	char *pwd;
	sysargs sys;
	jobs job;

	memset(&sys, 0, sizeof(sysargs));
	memset(&job, 0, sizeof(jobs));

	while ((ch = getopt(argc, argv, "a:j:cp:o:h")) != -1) {
		switch (ch) {
			case 'j':

				if (atoi(optarg) < 1 || atoi(optarg) > 9) {
					err = -EINVAL;
					goto out;
				}

				sys.jobtype = atoi(optarg);

				switch (sys.jobtype) {
					case ENCRYPTION:
						sys.isEncrypt = 1;
						break;
					case DECRYPTION:
						sys.isDecrypt = 1;
						break;
					case COMPRESS:
						sys.isCompress = 1;
						break;
					case DECOMPRESS:
						sys.isDecompress = 1;
						break;
					case CHECKSUM:
						sys.isCheckSum = 1;
						break;
					case LIST:
						sys.isList = 1;
						break;
					case REMOVE:
						sys.isRemove = 1;
						break;
					case REMOVE_ALL:
						sys.isRemoveAll = 1;
						break;
					case PRIORITY_CHANGE:
						sys.isPChange = 1;
						break;
					default:
						ret = -1;
						goto out;
				}

				break;

			case 'p':
				sys.isPassword = 1;
				pwd = optarg;
				if  (strlen(pwd) < 6) {					
					err = -EINVAL;
					goto out;
				}

				MD5((const unsigned char *)pwd, strlen(pwd), sys.hash);
				break;

			case 'o':
				if (atoi(optarg) < 1 || atoi(optarg) > 3) {
					err = -EINVAL;
					goto out;
				}

				sys.isPriority = 1;
				sys.priority = atoi(optarg);
				break;

			case 'h':
				displayMessage(argv[0]);
				break;

			case 'c':
				sys.isCallBack = 1;
				break;

			case 'a':
				if (atoi(optarg) != MD5_ALGO && atoi(optarg) != SHA_ALGO) {
					err = -EINVAL;
					goto out;
				}

				sys.isAlgo = 1;
				sys.algoType =  atoi (optarg);
				break;

			default:
				err = -EINVAL;
				goto out;
		}
	}

	if (sys.jobtype == 0 && sys.isCallBack == 0) {		
		err = -EINVAL;
		goto out;
	}

	ret = validate_and_parse_options (&sys, &job, argc, argv);
	
	if (ret != 0) {
		err = -EINVAL;
		goto out;
	}

	if (sys.isCallBack == 1) {
		pthread_create(&thread1, NULL, (void *) &netlink_callback, NULL);
        pthread_create(&t_timer, NULL, (void *)&timer_thread, NULL);
	}
	
	ret =  syscall(__NR_submitjob, (void *)&job, sizeof(job));

	if (ret < 0) {	
		perror("Error: ");
		goto exit_point;
	}

	if (sys.isList == 1 || sys.isRemove == 1 || sys.isRemoveAll == 1 || sys.isPChange == 1) {
		printf("%s\n", job.outfile);
		goto exit_succ;
	}

	if (sys.isCallBack == 1) {
		pthread_create(&thread2, NULL, (void *) &displayCounter, NULL);
		pthread_join(thread1, NULL);
		pthread_join(thread2, NULL);
	}

	if (job.infile != NULL)
		free(job.infile);

	if (job.outfile != NULL)
		free(job.outfile);

exit_succ:
	return 1;

out:
	printf("Invalid Arguments Passed! Type -h for help.\n");

exit_point:
	return -1;
}
