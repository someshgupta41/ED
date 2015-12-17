#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stddef.h>
#include <openssl/md5.h>
#include "sys_xcrypt.h"

/*Error number*/
extern int errno;

// structure to store and perform operations on the command options specified by the user
typedef struct command_options {

	int encryptionFlag, decryptionFlag;
	int cipherAlgoFlag;
	int passwordFlag;
	int passwordLen;
	char *password;
	char *cipherAlgo;
	char *inputFile;
	char *outputFile;
} cmd_opt1;


// Function to display the help message to the user.
void displayMessage(char *string) {
	fprintf(stdout, "Usage : %s {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] inputFile outputFile \n", string);
	fprintf(stdout, "{-e|-d} Use this options to specify whether you want to encrypt or decrypt the inputfile\n");
	fprintf(stdout, "[-c ARG] Optional Argument. This option specifies the cipher Algorithm which you want to use for Encryption.The default Encryption method used is AES\n" );
	fprintf(stdout, "-p This option is used to specify the password. E.g. -p 'password123'\n" );
	fprintf(stdout, "-h Used to display the help message to outline the process on how to use the file\n" );
	fprintf(stdout, "inputfile : specifies the inputfile to be encrypted/decrypted (with the path name)\n");
	fprintf(stdout, "outputfile : specifies the outputfile to be encrypted/decrypted (with the path name)\n");

}

// Function to parse and validate over the command line options specified by the user
int validate_and_parse_options(cmd_opt1 *cmd_opt, int argc, char **argv) {

	// Used for the iterating over the parameters specified by the user at command line
	int opt_char;

	// Used to keep track of any invalid option specified by the user.
	int errorFlag = 0;

	// Hardcoding the default value of the cipher Algo to be used as "AES".
	cmd_opt->cipherAlgo  = "AES" ;

	// Iterating over the list of option specified by the user at the command line.
	while ((opt_char = getopt(argc, argv, "edc:p:h")) != -1) {
		switch (opt_char) {

		// set the encryption flag if the one of the parameter supplied is '-e'
		case 'e' :
			cmd_opt->encryptionFlag = 1;
			break;

		// set the decryption flag if the one of the parameter supplied is '-d'
		case 'd' :
			cmd_opt->decryptionFlag = 1;
			break;

		// setting the cipherAlgo flag to denote that the user has specified the optional parameter.
		// defaulting to "AES" as the method to be used for Encryption.
		case 'c' :
			cmd_opt->cipherAlgoFlag = 1;
			cmd_opt->cipherAlgo = "AES";
			break;

		// setting the password flag to 1 to denote that the user has specified the mandatory password parameter
		// setting the password specified by the user in the password field of the structure.
		case 'p' :
			cmd_opt->passwordFlag = 1;
			cmd_opt->password = optarg;
			break;

		// Displays the help message informing the user about how to go about using the command.
		case 'h' :
			displayMessage(argv[0]);
			return 2;
			break;

		// Setting the error flag in case the user specifies any invalid option at the command line.
		default:
			errorFlag = 1;
		}
	}

	cmd_opt->inputFile = argv[optind];
	cmd_opt->outputFile = argv[optind + 1];

	// Informing the user about the correct usage incase an invalid option has been specified.
	if (errorFlag == 1) {
		fprintf(stderr, "Invalid option specified.Please provide a valid option.\n");
		fprintf(stderr, "Usage : %s {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] inputFile outputFile\n", argv[0]);
		return -1;
	}

	// Checks if both or none of the encryption and decryption options have been specified.
	else if (cmd_opt->encryptionFlag == cmd_opt->decryptionFlag) {
		fprintf(stderr, "Both/none of the Encryption or Decryption options have been specified. Please provide exactly one of them.\n");
		fprintf(stderr, "Usage : %s {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] inputFile outputFile\n", argv[0]);
		return -1;
	}

	// Checks and intimates the user if the mandatory password option has not been specified.
	else if (cmd_opt-> passwordFlag == 0) {
		fprintf(stderr, "Password has not been specified. Please provide a password.\n");
		fprintf(stderr, "Usage : %s {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] inputFile outputFile\n", argv[0]);
		return -1;
	}

	// MANDATORY password field has to be specified. It is not OPTIONAL.
	else if (cmd_opt->password == NULL)
	{
		fprintf(stderr, "Password not mentioned.");
		return -1;
	}

	// Password length has to be at least 6 characters.
	else if (strlen(cmd_opt->password) < 6) {
		fprintf(stderr, "password length is too small.Password should be greater than 6 characters.\n");
		return -1;
	}

	// Tells the user that it is MANDATORY to specify the input file to be encrypted/decrypted.
	else if (cmd_opt->inputFile == NULL)
	{
		fprintf(stderr, "Input File has not been specified.\n");
		fprintf(stderr, "Usage : %s {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] inputFile outputFile\n", argv[0]);
		return -1;
	}

	// Tells the user that it is MANDATORY to specify the output file to be encrypted/decrypted.
	else if (cmd_opt->outputFile == NULL) {
		fprintf(stderr, "Output File has not been specified.\n");
		fprintf(stderr, "Usage : %s {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] inputFile outputFile\n", argv[0]);
		return -1;
	}

	// Prompts the user in case additional options have been specified
	else if (((optind + 2) != argc)) {
		fprintf(stderr, "Usage : ./xcipher {-e|-d} [-c ARG] {-p PASSWORD} [-h HELP] inputFile outputFile \n");
		return -1;
	}

	// return 0 , in case everything goes well.
	return 0;
//return 0;
}

int main(int argc, char *argv[])
{
	// checks if the validate_and_parse_options function returned successfully.
	int checkOptions = -1;
	// parameter to check if the syscall to sys_xcrypt() returned successfully.
	long systemcallReturnValue = 0;
	// instance of the cmd_opt1 structure that is used to perform user level validation.
	cmd_opt1 opt1;
	// The HASH that will store the MD5 hash of the password specified by the user.
	unsigned char HASH[MD5_DIGEST_LENGTH];
	// Structure that will contain the required parameters for making the syscall.
	struct kl_mod_args user_argument;


	// Variable that stores the password length specified by the user.
	int passwordLen;
	// initializing the instance of kl_mod_args structure.
	memset(&user_argument, 0, sizeof(user_argument));
	// Initialing the instance of the cmd_opt1 structure.
	memset(&opt1, 0, sizeof(opt1));
	// Function call to check and validate the command-line options
	checkOptions = validate_and_parse_options(&opt1, argc, argv);
	if (checkOptions == 2)
		return 0;
	// If the validate_and_parse_options returned successfully,proceed.
	if (checkOptions == 0)
	{
		passwordLen =  strlen(opt1.password);
		// Compute the MD5 hash of the user PASSWORD
		MD5((const unsigned char*) opt1.password, passwordLen, HASH);
		// Assign the computed MD5 hash to the keyBuffer field of the instance of the kernel_level structure.
		user_argument.keybuf = (char*) HASH;

		// Assign the input file to the corresponding field of the kernel level structure.
		user_argument.infile = opt1.inputFile ;
		// Assign the output file to the corresponding field of the kernel level structure.
		user_argument.outfile = opt1.outputFile;


		// Assign the flag depending upon whether the user wants to encrypt or decrypt the file,
		user_argument.encdecflag = (opt1.encryptionFlag == 1) ? 1 : 0;
		//  Length of the KeyBuffer will be equal to the MD5 digest length.
		user_argument.keylen = MD5_DIGEST_LENGTH;


		// SYSTEM CALL to the sys_xcrypt
		systemcallReturnValue =  syscall(__NR_xcrypt, (void*)&user_argument);
		// If the system call was not successful, display the appropriate message to the user.
		if (systemcallReturnValue != 0)
		{
			switch (errno)
			{
			case 1 : // EPERM => Operation not permitted
				fprintf(stderr, "Operation being performed is not permitted\n");
				break;
			case 2:  //ENOENT  => No such file or directory
				fprintf(stderr, "Unable to access the input/output file.Either it does not exist or it does not have the required access rights.\n");
				break;
			case 14:  //EFAULT => Bad Address
				fprintf(stderr, "Unable to access the input parameters (or) Unable to perform Encryption/Decryption.\n");
				break;
			case 30:  //EROFS => Read only File System
				fprintf(stderr, "It's a read-only file system.Unable to perform the required operations.");
				break;
			case 36:  // ENAMETOOLONG => The input/output file name path provided is too long
				fprintf(stderr, "Input file name (path) or Output file name (path) too long");
				break;
			case 38 :  //Input and the output file are the same
				fprintf(stderr, "Input and Output file are the same.\n");
				break;
			case 50: // Password for encryption and decryption do not match
				fprintf(stderr, "Passwords used for encryption and decryption do not match or the input file is not encrypted to perform decryption.\n");
				break;
			case 90: // EMSGSIZE => Message too long
				fprintf(stderr, "User password should be between 6-4096 characters\n");
				break;

			case 22 :
				fprintf(stderr, "\nInvalid Argument passed. (or) InputFile may be empty. Skipping encryption/Decryption\n");

			// default message based on kernel error code.
			default:
				perror("failed !!");
				break;
			}

		}
	}
	else {
		//fprintf(stderr, "Not able to validate the options.Exiting !!");
		return -1;
	}

	exit(systemcallReturnValue);
}
