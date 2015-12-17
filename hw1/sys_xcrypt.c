#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include "sys_xcrypt.h"
#include <linux/scatterlist.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/md5.h>


#define MD5_DIGEST_LENGTH 16
#define MAX_ALLOW_PATH_SIZE 254
#define AES_BLOCK_SIZE 16
#define MINIMUM_BUFFER_SIZE 6
#define MAXIMUM_BUFFER_SIZE 4095
#define IV "guptasomeshasdrt"
const u8 (*aes_iv) = (u8*) IV;

/*

This function performs some basic checks on the userArguments passed to the Kernel.
The followed check is performed to be double sure that the arguments passed are valid
before allocating them any physical memory by the kernel.Once the arguments are verified
the kernel copies them from the user space to the kernel space .It performs the following checks :
		1) Check if the pointer to the structure passed is accessible
		2) Check if the arguments are NULL
		3) Check if the password entered by the user is between 6-4096
		4) Check if the input file path is too long
		5) Check if the output file is too long

Input : a pointer to the structure to be validated
Output : If valid return zero, else return the corresponding errNo.

*/
long validateUserArguments(void *argument)
{
	args *validatePtr = (args *) argument;

	/* verify that the pointer is accessible */
	if (validatePtr == NULL ||
	        unlikely(!access_ok(VERIFY_READ, validatePtr, sizeof(args))))
		goto error;
	/* verify that the input file name passed is accessible*/
	if (validatePtr->infile == NULL ||
	        unlikely(!access_ok(VERIFY_READ,
	                            validatePtr->infile, sizeof(validatePtr->infile))))
		goto error;
	/* verify that the pointer to the output file name is valid*/
	if (validatePtr->outfile == NULL ||
	        unlikely(!access_ok(VERIFY_READ,
	                            validatePtr->outfile, sizeof(validatePtr->outfile))))
		goto error;
	/* verify that the pointer to the password passed is valid and keybuf and keylen are the same length*/
	if (validatePtr->keybuf == NULL ||
	        unlikely(!access_ok(VERIFY_READ, validatePtr->keybuf, validatePtr->keylen)))
		goto error;
	/* verify if the inputFile and the outputFile passed are within the permissible limit */
	if ((strlen(validatePtr->infile) > MAX_ALLOW_PATH_SIZE) ||
	        (strlen(validatePtr->outfile) > MAX_ALLOW_PATH_SIZE))
		goto path_name_too_long;
	/* verify if the password entered lies between the maximum and the minimum buffer range*/
	if ((strlen(validatePtr->keybuf) + 1 < MINIMUM_BUFFER_SIZE) &&
	        (strlen(validatePtr->keybuf) + 1 > MAXIMUM_BUFFER_SIZE))
		goto password_too_long;
	return 0;

error:
	return -EFAULT;
path_name_too_long:
	return -ENAMETOOLONG;
password_too_long:
	return -EMSGSIZE;
}

/*
This function performs the required encryption of the password. The mode used to perform this encryption is CTR mode.The source-code of this function is copied from /net/ceph/crypto.c and has been modified to suit the given requirements

		Input :
		1) The user password or key to be used for encryption
		2) The key length of the password
		3) The destination buffer to which the encrypted data will be written into
		4) The destination buffer length
		5) The source buffer containing the data to be encrypted.
		6) The length of the source buffer.

		Output:
		1) returns 0 if the function succeeds otherwise it returns a non-zero value.
*/

static int functionToEncrypt(const void *key, int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len)
{
	//scatter list declaration for input and output buffers.
	struct scatterlist sg_in[1], sg_out[1];
	//Initialising transformation object to register it for the CTR mode of AES
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
	// Creates a block_cipher_description object with the required parameters
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	// The return value of the function
	int ret;
	// A pointer to the initialization vector
	void *iv;
	int ivsize;

	// return if there seems to be an error in allocating the transformation object
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);


	// Initializing the input buffer
	sg_init_table(sg_in, 1);
	sg_set_buf(&sg_in[0], src, src_len);


	// Initializing the output buffer
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, dst, *dst_len);

	// Initializing the cipher key for the blockcipher operation
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	// Initialize the IV
	iv = crypto_blkcipher_crt(tfm)->iv;
	// Determine the IV size
	ivsize = crypto_blkcipher_ivsize(tfm);


	memcpy(iv, aes_iv, ivsize);


	// Call the block cipher encrypt API to perform CTR(AES) encryption.
	ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, src_len);
	if (ret < 0) {
		pr_err("crypto_aes_encrypt failed %d\n", ret);
	}

	// Exit the function by freeing the transformation object
	crypto_free_blkcipher(tfm);
	return ret;
}


/*
This function performs the required decryption of the password.The mode used to perform this decryption is CTR.The source-code of this function is copied from /net/ceph/crypto.c and has been modified to suit the given requirements

		Input :
		1) The user password or key to be used for encryption
		2) The key length of the password
		3) The destination buffer to which the encrypted data will be written into
		4) The destination buffer length
		5) The source buffer containing the data to be encrypted.
		6) The length of the source buffer.

		Output:
		1) returns 0 if the function succeeds otherwise it returns a non-zero value.
*/
static int functionToDecrypt(const void *key, int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len)
{
	// Declare the scatterlist for the input and output buffers
	struct scatterlist sg_out[1], sg_in[1];
	//Initialising transformation object to register it for the CTR mode of AES
	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
	// Creates a block_cipher_description object with the required parameters
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };

	// A pointer to the initialization vector
	void *iv;
	int ivsize;
	// The return value of the function
	int ret;

	// return if there seems to be an error in allocating the transformation object
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);


	// Initializing the output buffer
	sg_init_table(sg_out, 1);
	sg_set_buf(&sg_out[0], dst, *dst_len);


	// Initializing the input buffer
	sg_init_table(sg_in, 1);
	sg_set_buf(sg_in, src, src_len);


	// Initializing the cipher key for the blockcipher operation
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	// Initialize the IV
	iv = crypto_blkcipher_crt(tfm)->iv;
	// Determine the IV size
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);


	// Call the block cipher encrypt API to perform CTR(AES) encryption.
	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
	if (ret < 0) {
		pr_err("crypto_aes_decrypt failed %d\n", ret);
	}

	// Exit the function by freeing the transformation object
	crypto_free_blkcipher(tfm);
	return ret;
}


/*
This function performs the MD5 hashing of the user entered password in the kernel space, before sending the double hashed password for encryption which, is later
written into the output file. The source-code for this function has been copied from linux/fs/ecryptfs/crypto.c and has been modified to match the requirements.

		Input :
		1) A pointer to the destination buffer string into which the calculated hashed password is written.
		2) A pointer to the source buffer string from which the hashed password from user space is fetched.
		3) The length of the HASHED password , which is equal to the MD5_DIGEST_LENGTH.

		Output :
		1) An integer equal to zero, if the function successfully calculates MD5, otherwise it returns a non-zero number.

*/
static int ecryptfs_calculate_md5(char *dst, char *src, int len)
{
	//Declare the scatterlist for generating the hash
	struct scatterlist sg;

	//Initialize the hash_descriptors
	struct hash_desc desc = {.tfm = NULL, .flags = CRYPTO_TFM_REQ_MAY_SLEEP};
	
	int error_val = 0;
	
	// Initialize the scatter list
	sg_init_one(&sg, (u8 *)src, len);

	//Initialize the hash descriptor 
	desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

	// Return if there is some error while allocating the transformation object
	if (!desc.tfm || IS_ERR(desc.tfm)) {
		error_val = PTR_ERR(desc.tfm);
		goto return_error;
	}

	//Initialize the crypto hash with the details populated in the descriptor
	error_val = crypto_hash_init(&desc);
	if (error_val) {
		goto return_error;
	}

	//Update the crypto hash with the details of the descriptor
	error_val = crypto_hash_update(&desc, &sg, len);
	if (error_val) {
		goto return_error;
	}

	//Copy the hash computed in the destination buffer
	error_val = crypto_hash_final(&desc, dst);
	if (error_val) {
		goto return_error;
	}

return_error:
	return error_val;
}

/*
This function is used to open an INPUT file in the required mode and return a fileHandle to the calling function to perform further operations.
*/
struct file* openInputFile(char *inputFileToOpen)
{
	struct file *fileHandle = NULL;
	if (inputFileToOpen != NULL) {
		fileHandle = filp_open(inputFileToOpen, O_EXCL | O_RDONLY, 0);
	}

	return fileHandle;
}

/*
This function is used to open an OUTPUT file in the required mode and return a fileHandle to the calling function to perform further operations.
*/


struct file* openOutputFile(char *outFileToOpen, umode_t mode)
{
	struct file *fileHandle = NULL;
	if (outFileToOpen != NULL) {
		fileHandle = filp_open(outFileToOpen, O_WRONLY | O_CREAT, mode);

	}
	return fileHandle;
}


/*
This function is used to copy the required parameters from the user space to the kernel space. The kernel allocated physical memory to the objects.
		Input:
		1) A pointer to the user space structure to be copied data from .
		2) A pointer to the kernel space structure to be copied data into.
		Output :
		An integer, if 0 the transfer of data from the user space to the kernel space was successful.
		Otherwise, return a non-zero value.
*/

int transportUserDataToKernel(args *userAdd, args* kernelAdd)
{
	int err = 0;

	if ((err = copy_from_user(&kernelAdd->encdecflag, &userAdd->encdecflag, sizeof(int))) != 0)
		goto out;

	if ((err = copy_from_user(&kernelAdd->keylen, &userAdd->keylen, sizeof(int))) != 0)
		goto out;

	 

	kernelAdd->outfile = kmalloc(strlen(userAdd->outfile) + 1, GFP_KERNEL);
	if (!kernelAdd->outfile) {
		err = -ENOMEM;
		goto error_in_outfile_mem;
	}

	if ((err = copy_from_user(&kernelAdd->outfile, &userAdd->outfile, sizeof(int))) != 0)
		goto error_in_outfile_mem;
	kernelAdd->outfile[strlen(userAdd->outfile)] = '\0';

	/* allocate memory to store key buffer and copy */
	kernelAdd->keybuf = kmalloc(strlen(userAdd->keybuf) + 1, GFP_KERNEL);
	if (!kernelAdd->keybuf) {
		err = -ENOMEM;
		goto error_in_key_buff;
	}
	if ((err = copy_from_user(kernelAdd->keybuf,
	                          userAdd->keybuf,
	                          strlen(userAdd->keybuf))) != 0)
		goto error_in_key_buff;
	kernelAdd->keybuf[strlen(userAdd->keybuf)] = '\0';


	return err;

	error_in_infile_mem:
		kfree(kernelAdd->infile);
	error_in_key_buff:
		kfree(kernelAdd->keybuf);
	error_in_outfile_mem:
		kfree(kernelAdd->outfile);
	out:
		return err;
}

asmlinkage extern long (*sysptr)(void *arg);

asmlinkage long xcrypt(void *arg)
{
	int ret = 0, valid;

	//The file handlers for the input,output and temporary files
	struct file *inHandle = NULL, *outHandle = NULL, *outHandle1 = NULL; 
	
	//
	mm_segment_t oldfs;
	int inputFileSize = -1;
	int outputFileSize = -1;
	int flag ;
	char *tempfile;
	umode_t inputFileMode ;
	umode_t outputFileMode;
	unsigned char *newMD5 = NULL;
	char *buf, *encrypt_buf, *decrypt_buf;
	char *hash_decrypt_buf, *hash_encrypt_buf;
	unsigned char *hashed_pass_from_file;
	char *tmp_buf = NULL;
	int rc;
	int len = AES_BLOCK_SIZE;
	struct inode *outputfile_inode, *outputfile1_inode;
	struct dentry *outputfile_dentry = NULL;
	struct dentry *outputfile1_dentry = NULL;
	//int crypt_size;
	int hashenc = 0, hashdec = 0;
	int toDecryptOrEncrypt;
	int alreadyCreated = 0;
	args *k = (args*) arg;
	if (arg == NULL)
	{
		ret = -EINVAL;
		goto md5_hash_fail;

	}


	valid = validateUserArguments(arg);

	if (valid == 0)
	{
		k = kmalloc(sizeof(args), GFP_KERNEL);
		if (!k) {
			ret = -ENOMEM;
			goto in_file_fail;
		}
		memset(k, 0, sizeof(args));
		ret = transportUserDataToKernel(arg, k);
		if (ret != 0) {
			ret = -ENOMEM;
			goto in_file_fail;
		}


		newMD5 = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		if (!newMD5) {
			ret = -ENOMEM;
			goto md5_hash_fail;
		}
		memset(newMD5, 0, AES_BLOCK_SIZE);


		/*Compute the MD5 Hash*/
		rc = ecryptfs_calculate_md5(newMD5, (char*)k->keybuf, MD5_DIGEST_LENGTH);

		if (rc != 0)
		{
			return ret;
		}

		if (k->infile != NULL)
			inHandle = openInputFile(k->infile);

		if (!inHandle || IS_ERR(inHandle)) {
			return -EFAULT;  /* or do something else */

		}
		if (!(inHandle->f_op)) {
			filp_close(inHandle, NULL);
			inHandle = NULL;
			ret = -EFAULT;
			goto error;
		}
		if (!inHandle->f_op->write) {
			filp_close(inHandle, NULL);
			inHandle = NULL;
			ret = -EFAULT;
			goto error;
		}

		if (!inHandle->f_op->read)
		{
			ret = -EPERM;
			goto error;  /* file(system) doesn't allow reads */
		}

		inputFileSize = inHandle->f_path.dentry->d_inode->i_size;
		inputFileMode = inHandle->f_path.dentry->d_inode->i_mode;
		if (!(S_ISREG(inputFileMode)))
		{
			ret = -EINVAL;
			goto error;
		}

		if (k->outfile != NULL)
		{
			outHandle = openInputFile(k->outfile);
			if (outHandle != NULL)
				alreadyCreated = 1;
			outHandle = openOutputFile(k->outfile, 0);
		}

		if (!outHandle || IS_ERR(outHandle)) {
			ret = -EFAULT;
			goto error;
		}

		if (!(outHandle->f_op)) {
			filp_close(outHandle, NULL);
			outHandle = NULL;
			ret = -EFAULT;
			goto error;
		}
		if (!outHandle->f_op->write) {
			filp_close(outHandle, NULL);
			outHandle = NULL;
			ret = -EFAULT;
			goto error;
		}

		/*Return if the file system doesn't handle write operations*/
		if (!outHandle->f_op->write)
		{
			ret = -EPERM;
			goto error;  
		}

		/*Compute the output file mode to check if its a regular file*/
		outputFileMode = outHandle->f_path.dentry->d_inode->i_mode;

		if (!(S_ISREG(outputFileMode)))
		{
			ret = -EINVAL;
			goto error;
		}


		outputfile_dentry = outHandle->f_path.dentry;
		outputfile_inode = (struct inode*) outHandle->f_path.dentry->d_parent->d_inode;

		if ((inHandle->f_path.dentry->d_inode->i_ino == outHandle->f_path.dentry->d_inode->i_ino) &&
		        (inHandle->f_path.dentry->d_inode->i_sb == outHandle->f_path.dentry->d_inode->i_sb))
		{
			ret = -38;
			goto error;
		}




		tempfile = strcat(k->outfile, ".tmp");
		outHandle1 = openOutputFile(tempfile, 0);

		if (!outHandle1 || IS_ERR(outHandle1)) {
				ret = -EFAULT;
				goto error;
		}

		if (!(outHandle1->f_op)) {
			filp_close(outHandle1, NULL);
			outHandle1 = NULL;
			ret = -EFAULT;
			goto error;
		}
		if (!outHandle1->f_op->write) {
			filp_close(outHandle1, NULL);
			outHandle1 = NULL;
			ret = -EFAULT;
			goto error;
		}



		outputfile1_dentry = outHandle1->f_path.dentry;
		outputfile1_inode = (struct inode*)outHandle1->f_path.dentry->d_parent->d_inode;



		if (!outHandle1->f_op->write)
		{
			ret = -EPERM;
			goto error;  /* file(system) doesn't allow reads */
		}


		/* now read len bytes from offset 0 */
		buf = (char *) kmalloc(PAGE_SIZE, GFP_KERNEL);
		memset(buf, 0, PAGE_SIZE);

		hash_encrypt_buf = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		memset(hash_encrypt_buf, 0, AES_BLOCK_SIZE);

		hash_decrypt_buf = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		memset(hash_decrypt_buf, 0, AES_BLOCK_SIZE);

		encrypt_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		memset(encrypt_buf, 0, PAGE_SIZE);
		decrypt_buf =  kmalloc(PAGE_SIZE, GFP_KERNEL);
		memset(decrypt_buf, 0, PAGE_SIZE);

		tmp_buf = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		memcpy(tmp_buf, k->keybuf, AES_BLOCK_SIZE);

		hashed_pass_from_file = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
		memset(hashed_pass_from_file, 0, AES_BLOCK_SIZE);

		inHandle->f_pos = 0;		/* start offset */
		outHandle->f_pos = 0;
		outHandle1->f_pos = 0;
		oldfs = get_fs();
		set_fs(KERNEL_DS);

		toDecryptOrEncrypt = (k->encdecflag) & 1;

		if ((toDecryptOrEncrypt) == 1)
		{

			hashenc = functionToEncrypt(hash_encrypt_buf, &len, newMD5, AES_BLOCK_SIZE);
			if (hashenc < 0)
			{
				ret = -EBADF;
				return ret;
			}
			outHandle1->f_op->write(outHandle1, hash_encrypt_buf, AES_BLOCK_SIZE, &outHandle1->f_pos);

			while ((ret = inHandle->f_op->read(inHandle, buf, PAGE_SIZE, &inHandle->f_pos)) > 0)
			{
				flag = functionToCompress(encrypt_buf, &ret, buf, ret);
				if (flag == 0)
					outHandle1->f_op->write(outHandle1, encrypt_buf, ret, &outHandle1->f_pos);
			}

		}
		else
		{

			inHandle->f_op->read(inHandle, hash_decrypt_buf, AES_BLOCK_SIZE, &inHandle->f_pos);

			hashdec = functionToDecrypt(tmp_buf, AES_BLOCK_SIZE, hashed_pass_from_file, &len, hash_decrypt_buf, AES_BLOCK_SIZE);

			if (hashdec < 0)
			{
				ret = -EBADF;
				return ret;
			}

			if (strncmp(hashed_pass_from_file, newMD5, AES_BLOCK_SIZE) != 0)
			{
				outputFileSize = outHandle->f_path.dentry->d_inode->i_size;
				outputFileMode = outHandle->f_path.dentry->d_inode->i_mode;

				if (outputFileSize == 0)
				{
					vfs_unlink(outputfile1_inode, outputfile1_dentry, NULL);
					vfs_unlink(outputfile_inode, outputfile_dentry, NULL);
				}
				else
				{
					vfs_unlink(outputfile1_inode, outputfile1_dentry, NULL);
				}
				ret = -50;
				goto error;
			}

			while ((ret = inHandle->f_op->read(inHandle, buf, PAGE_SIZE, &inHandle->f_pos)) > 0)
			{
				flag = functionToDecrypt(tmp_buf, AES_BLOCK_SIZE, decrypt_buf, &ret, buf, ret);
				if (flag == 0)
					outHandle1->f_op->write(outHandle1, decrypt_buf, ret, &outHandle1->f_pos);
			}

		}





		if (ret < 0)
		{
			if (outputfile_dentry != NULL && outputfile_inode != NULL)
			{
				vfs_unlink(outputfile1_inode, outputfile1_dentry, NULL);
			}
		}
		else
			vfs_rename(outputfile1_inode, outputfile1_dentry, outputfile_inode, outputfile_dentry, NULL, 0);




		set_fs(oldfs);
		/* close the file */
		filp_close(inHandle, NULL);
		filp_close(outHandle, NULL);

error:
		return ret;

md5_hash_fail:
		kfree(newMD5);
		return ret;
in_file_fail:
		return ret;
	}
	else
	{
		return -EPERM;
	}

}


static int __init init_sys_xcrypt(void)
{
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}

static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("SOMESH");
MODULE_DESCRIPTION("xcrypt() system call : used to perform Encryption and Decryption of Files.");
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);

