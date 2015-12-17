#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <asm/ioctls.h>
#include <linux/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/kernel.h>
#include <linux/fs.h> 
#include <linux/version.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mntent.h>
#include <errno.h>

#include "amfsctl_header.h"


/*display message for the ioctl command*/
void displayMessage(char *string) {
	fprintf(stdout, "Usage : %s {-l|-a|-r} pattern [-h HELP] mount_point_of_AMFS \n", string);
	fprintf(stdout, "{-l} : Use this option to specify when you want to list the patterns from patternDb\n");
	fprintf(stdout, "{-a} : Use this option to specify when you want to add a pattern to the patternDb\n");
	fprintf(stdout, "{-r} : Use this option to specify when you want to remove a pattern from patternDb\n");
	fprintf(stdout, "pattern : pattern to be added/removed\n");
	fprintf(stdout, " -h  : Used to display the help message to outline the process on how to use the ioctl\n" );
	fprintf(stdout, "mount_point_of_AMFS : the point where the AMFS is mounted\n");
}


int main(int argc,char* argv[]){

	// get the page size to be used for allocating buffer size
	int PAGE_SIZE = getpagesize();
	// allocate the buffer of page_size length
	char buffer[PAGE_SIZE];
	// 
	char mount_point[PAGE_SIZE];
	int parse_options =0;	
	//memset(&buffer,0,sizeof(buffer));
	
	// flags to indicate which option has been specified
	int addFlag=0,removeFlag=0,helpFlag=0,listFlag=0;
	// File descriptor to be passed to ioctl
	int fileDescriptor = -1;
	// errorFlag to be set in case of an invalid option
	int errorFlag = 0;
	// returnval to be sent on success
	int returnVal =0;
	
	//Parse the options specified at the command line 
	while ((parse_options = getopt(argc, argv, "a:r:lh")) != -1) {
		switch (parse_options) {
	// the option to remove patterns
		case 'l' :
		// set the listFlag
			listFlag = 1;
			break;
	// the option to add patterns 
		case 'a' :
		// set the addFlag
			addFlag = 1;
		// assign a buffer of page_size and copy the command-line argument to buffer
			memset(&buffer,0,sizeof(buffer));
			strcpy(buffer,optarg);	
			break;
	// the remove option
		case 'r' :
		// set the removeFlag
			removeFlag = 1;
		// assign a buffer of page_size and copy the command-line argument to buffer
			memset(&buffer,0,sizeof(buffer));
			strcpy(buffer,optarg);	
			break;
	// the option to specify help on how to use ioctl 
		case 'h' :
		// set the helpFlag
			helpFlag=1;
			displayMessage(argv[0]);
			return 0;
		default:
			errorFlag = 1;
		}
	}

	//check to validate the options
	if((listFlag == 1 && argc!=3) || (removeFlag == 1 && argc!=4) || (addFlag == 1 && argc!=4) || argc < 3 || argc > 4)
	{
		printf(" Please check the usage.\n");
		fprintf(stderr, "Usage : %s {-l|-a|-r} [-h HELP] mount_point_of_AMFS \n", argv[0]);
		return -1;
	}
	//invalid option specified
	else if (errorFlag == 1) {
		fprintf(stderr, "Usage : %s {-l|-a|-r} [-h HELP] mount_point_of_AMFS \n", argv[0]);
		return -1;
	}

	//copy the last argument into the mount_point buffer
 	memset(&mount_point,0,sizeof(mount_point));
	mount_point[strlen(argv[optind])]='\0';
 	strcpy(mount_point,argv[optind]);

 	// generate the file descriptor for the ioctl
	if ((fileDescriptor = open(mount_point, O_RDONLY)) < 0) {
		perror("open error");
		return -1;
	}

	// invoke the ioctl for the list option
	if(listFlag == 1 )
	{
		if(ioctl(fileDescriptor, LIST_IOCTL, buffer) < 0)
			perror("error in listing the ioctl");
		printf("%s" ,buffer );
	}
	// invoke the ioctl for the add option
	if(addFlag == 1)
	{	
		returnVal= ioctl(fileDescriptor, ADD_IOCTL,buffer);
		if( errno == 17)
			{
				fprintf(stderr, " The pattern %s already exists\n",buffer);
				return 0;
			}
		if(returnVal < 0)
		{
			perror("error in adding pattern through ioctl");
		}
	}
	// invoke the ioctl for the remove option
	if(removeFlag == 1)
	{
		returnVal= ioctl(fileDescriptor, REMOVE_IOCTL,buffer);
		if( errno == 42)
			{
				fprintf(stderr, " The pattern %s does not exist in the patternDb \n",buffer);
				return 0;
			}
		if(returnVal < 0)
		{
			perror("error in removing pattern through ioctl");
		}
		
	}
return 0;
	}


