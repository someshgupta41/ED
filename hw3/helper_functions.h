#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <asm/uaccess.h>
#include <asm/string.h>
#include <linux/kernel.h>
#include <asm/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <crypto/hash.h>

#define MD5_DIGEST_LENGTH 16
#define MAX_ALLOW_PATH_SIZE 254
#define AES_BLOCK_SIZE 16
#define MINIMUM_BUFFER_SIZE 6
#define MAXIMUM_BUFFER_SIZE 4095
#define SHA1_SIGNATURE_LENGTH 20

char *aes_iv  =  "someshkumargupta";

int functionToEncrypt (const void *key,   int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len)
 {
	struct scatterlist sg_in[1],   sg_out[1];
	struct crypto_blkcipher *tfm  =  crypto_alloc_blkcipher ("ctr(aes)",   0, CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc  =   { .tfm = tfm,   .flags = 0 };
	int ret;
	void *iv;
	int ivsize;

	if  (IS_ERR(tfm))
		return PTR_ERR (tfm);


	sg_init_table (sg_in,   1);
	sg_set_buf (&sg_in[0],   src, src_len);

	sg_init_table (sg_out,   1);
	sg_set_buf (sg_out,   dst, *dst_len);

	crypto_blkcipher_setkey ((void *)tfm,   key, key_len);
	iv  =  crypto_blkcipher_crt (tfm)->iv;
	ivsize  =  crypto_blkcipher_ivsize (tfm);

	memcpy (iv,   aes_iv, ivsize);
	ret  =  crypto_blkcipher_encrypt (&desc,   sg_out, sg_in, src_len);
	if  (ret < 0)  {
		pr_err ("crypto_aes_encrypt failed %d\n",   ret);
	}

	crypto_free_blkcipher (tfm);

	return ret;
}


int functionToDecrypt (const void *key,   int key_len, void *dst, size_t *dst_len, const void *src, size_t src_len)
 {
	struct scatterlist sg_out[1],   sg_in[1];
	struct crypto_blkcipher *tfm  =  crypto_alloc_blkcipher ("ctr(aes)",   0, CRYPTO_ALG_ASYNC);
	struct blkcipher_desc desc  =   { .tfm = tfm,   .flags = 0 };

	void *iv;
	int ivsize;
	int ret;

	if  (IS_ERR(tfm))
		return PTR_ERR (tfm);


	sg_init_table (sg_out,   1);
	sg_set_buf (&sg_out[0],   dst, *dst_len);

	sg_init_table (sg_in,   1);
	sg_set_buf (sg_in,   src, src_len);

	crypto_blkcipher_setkey ((void *)tfm,   key, key_len);
	iv  =  crypto_blkcipher_crt (tfm)->iv;
	ivsize  =  crypto_blkcipher_ivsize (tfm);
	memcpy (iv,   aes_iv, ivsize);

	ret  =  crypto_blkcipher_decrypt (&desc,   sg_out, sg_in, src_len);
	if  (ret < 0)  {
		pr_err ("crypto_aes_decrypt failed %d\n",   ret);
	}

	crypto_free_blkcipher (tfm);

	return ret;
}


int functiontoPerformSHA1CheckSum (char *input_file,  char *output_file)
 {

	struct scatterlist sg;
	int i;
	int fileSize  = 0;
	struct hash_desc desc;
	mm_segment_t oldfs;
	int no_of_bytes_read  =  0;
	int returnVal  =  0;
	struct file *in_filp  =  NULL;
	struct file *out_filp  =  NULL;
	void *buf  =  NULL;
	char *HASH  =  NULL;
	char *hash_to_written  =  NULL;
	buf  =  kzalloc (PAGE_SIZE,  GFP_KERNEL);
	HASH  =  kzalloc (sizeof(char)*(SHA1_SIGNATURE_LENGTH),  GFP_KERNEL);
	hash_to_written  =  kzalloc (sizeof(char)*(2),  GFP_KERNEL);
	in_filp  =  filp_open (input_file,  O_RDONLY, 0);
	out_filp  =  filp_open (output_file,  O_WRONLY|O_CREAT|O_TRUNC, 0);


	fileSize  =   (unsigned int)in_filp->f_path.dentry->d_inode->i_size;

	desc.tfm  =  NULL;
	desc.flags  =  CRYPTO_TFM_REQ_MAY_SLEEP;

	if (!in_filp || IS_ERR(in_filp))  {
		printk (KERN_ERR "Unable to open the input file to compute the checksum");
		returnVal  =  PTR_ERR (in_filp);
		in_filp  =  NULL;
		goto out;
	}
	if (!in_filp->f_op->read)  {
		printk (KERN_ERR "Input File does not allow reads!!");
		returnVal  =  PTR_ERR (in_filp);
		in_filp  =  NULL;
		goto out;
	}

	if (!out_filp || IS_ERR(out_filp))  {
		printk (KERN_ERR "Unable to open the input file to compute the checksum");
		returnVal  =  PTR_ERR (out_filp);
		out_filp  =  NULL;
		goto out;
	}
	if (!out_filp->f_op->read)  {
		printk (KERN_ERR "Input File does not allow reads!!");
		returnVal  =  PTR_ERR (out_filp);
		out_filp  =  NULL;
		goto out;
	}

	out_filp->f_path.dentry->d_inode->i_mode =  in_filp->f_path.dentry->d_inode->i_mode;

	in_filp->f_pos  =  0;
	oldfs  =  get_fs ();
	set_fs (KERNEL_DS);


	desc.tfm  =  crypto_alloc_hash ("sha1",   0, CRYPTO_ALG_ASYNC);


	if  (!desc.tfm || IS_ERR(desc.tfm))  {
		returnVal  =  PTR_ERR (desc.tfm);
		goto out;
	}


	returnVal  =  crypto_hash_init (&desc);
	if  (returnVal < 0)  {
		goto out;
	}

	do  {
		no_of_bytes_read  =  in_filp->f_op->read (in_filp,   buf, PAGE_SIZE, &in_filp->f_pos);
		if  (no_of_bytes_read < 0)  {
			returnVal  =  no_of_bytes_read;
			goto out;
		}
		sg_init_one (&sg,   (void *) buf, no_of_bytes_read);
		returnVal  =  crypto_hash_update (&desc,   &sg, no_of_bytes_read);
		if  (returnVal < 0)  {
			printk (KERN_ERR "Error: crypto_hash_update() failed for id\n");
			returnVal  =  -EINVAL;
			goto memory_free_up;
		}
		if  (no_of_bytes_read < PAGE_SIZE)  {
			returnVal  =  crypto_hash_final (&desc,   HASH);
			if  (returnVal < 0)  {
				printk (KERN_ERR "Error: crypto_hash_final() failed for digest\n");
				returnVal  =  -EINVAL;
				goto memory_free_up;
			}
		}
	} while  (no_of_bytes_read >=  PAGE_SIZE);

	if (HASH   ==  NULL)  {
		printk (KERN_ERR "\nthe SHA1 hash is  NULL\n");
		returnVal  =  -1;
		goto out;
	}

	for  (i  =  0; i < 20; i++)  {
		sprintf (hash_to_written,  "%02x", HASH[i] & 0xFF);
		returnVal  =  out_filp->f_op->write (out_filp,   hash_to_written, 2, &out_filp->f_pos);
		if (returnVal < 0) {
			printk (KERN_ERR "\nNot able to write the checksum to the output_file\n");
			returnVal  =  -EINVAL;
			goto out;
		}
	}

memory_free_up:
	kfree (HASH);
	kfree (hash_to_written);
	kfree (buf);
	set_fs (oldfs);

out:
	if (in_filp != NULL)
		filp_close (in_filp,  NULL);
	return returnVal;


}


int functiontoPerformMD5CheckSum (char *input_file,  char *output_file)
 {

	struct scatterlist sg;
	int i;
	int fileSize  = 0;
	struct hash_desc desc;
	mm_segment_t oldfs;
	int no_of_bytes_read  =  0;
	int returnVal  =  0;
	struct file *in_filp  =  NULL;
	struct file *out_filp  =  NULL;
	void *buf  =  NULL;
	char *HASH  =  NULL;
	char *hash_to_written  =  NULL;
	buf  =  kzalloc (PAGE_SIZE,  GFP_KERNEL);
	HASH  =  kzalloc (sizeof(char)*(MD5_DIGEST_LENGTH),  GFP_KERNEL);
	hash_to_written  =  kzalloc (sizeof(char)*(2),  GFP_KERNEL);


	desc.tfm  =  NULL;
	desc.flags  =  CRYPTO_TFM_REQ_MAY_SLEEP;

	in_filp  =  filp_open (input_file,  O_RDONLY, 0);
	out_filp  =  filp_open (output_file,  O_WRONLY|O_CREAT|O_TRUNC, 0);
	fileSize  =   (unsigned int)in_filp->f_path.dentry->d_inode->i_size;


	if (!in_filp || IS_ERR(in_filp))  {
		printk (KERN_ERR "Unable to open the input file to compute the checksum");
		returnVal  =  PTR_ERR (in_filp);
		in_filp  =  NULL;
		goto out;
	}
	if (!in_filp->f_op->read)  {
		printk (KERN_ERR "Input File does not allow reads!!");
		returnVal  =  PTR_ERR (in_filp);
		in_filp  =  NULL;
		goto out;
	}

	if (!out_filp || IS_ERR(out_filp))  {
		printk (KERN_ERR "Unable to open the input file to compute the checksum");
		returnVal  =  PTR_ERR (out_filp);
		out_filp  =  NULL;
		goto out;
	}
	if (!out_filp->f_op->read)  {
		printk (KERN_ERR "Input File does not allow reads!!");
		returnVal  =  PTR_ERR (out_filp);
		out_filp  =  NULL;
		goto out;
	}

	out_filp->f_path.dentry->d_inode->i_mode =  in_filp->f_path.dentry->d_inode->i_mode;

	in_filp->f_pos  =  0;
	oldfs  =  get_fs ();
	set_fs (KERNEL_DS);



	desc.tfm  =  crypto_alloc_hash ("md5",   0, CRYPTO_ALG_ASYNC);



	if  (!desc.tfm || IS_ERR(desc.tfm))  {
		returnVal  =  PTR_ERR (desc.tfm);
		goto out;
	}



	returnVal  =  crypto_hash_init (&desc);
	if  (returnVal < 0)  {
		goto out;
	}

	do  {
		no_of_bytes_read  =  in_filp->f_op->read (in_filp,   buf, PAGE_SIZE, &in_filp->f_pos);
		if  (no_of_bytes_read < 0)  {
			returnVal  =  no_of_bytes_read;
			goto out;
		}
		sg_init_one (&sg,   (void *) buf, no_of_bytes_read);
		returnVal  =  crypto_hash_update (&desc,   &sg, no_of_bytes_read);
		if  (returnVal < 0)  {
			printk (KERN_ERR "Error: crypto_hash_update() failed for id\n");
			returnVal  =  -EINVAL;
			goto memory_free_up;
		}
		if  (no_of_bytes_read < PAGE_SIZE)  {
			returnVal  =  crypto_hash_final (&desc,   HASH);
			if  (returnVal < 0)  {
				printk (KERN_ERR "Error: crypto_hash_final() failed for digest\n");
				returnVal  =  -EINVAL;
				goto memory_free_up;
			}
		}
	} while  (no_of_bytes_read >=  PAGE_SIZE);

	if (HASH   ==  NULL) {
		printk (KERN_ERR "\nthe MD5 hash is  NULL\n");
		returnVal  =  -1;
		goto out;
	}

	for  (i  =  0; i < 16; i++)
		printk ("%02x",   HASH[i] & 0xFF);

	for  (i  =  0; i < 16; i++)  {
		sprintf (hash_to_written,  "%02x", HASH[i] & 0xFF);
		returnVal  =  out_filp->f_op->write (out_filp,   hash_to_written, 2, &out_filp->f_pos);
		if (returnVal < 0)  {
			printk (KERN_ERR "\nNot able to write the checksum to the output_file\n");
			returnVal  =  -EINVAL;
			goto out;
		}
	}

memory_free_up:
	kfree (HASH);
	kfree (hash_to_written);
	kfree (buf);
	set_fs (oldfs);

out:
	if (in_filp != NULL)
		filp_close (in_filp,  NULL);
	return returnVal;


}


int functionToCompress (char *input_file,  char *output_file)
 {
	struct file *in_filp  =  NULL;
	struct file *out_filp  =  NULL;
	mm_segment_t oldfs;
	int no_of_bytes_read  =  0;
	int no_of_bytes_written  = 0;
	int dst_len ;
	int returnVal  =  0;
	int fileSize  =  0;
	void *buf  =  NULL;
	char *dst  =  NULL;
	struct crypto_comp *tfm;

	in_filp  =  filp_open (input_file,  O_RDONLY, 0);
	out_filp  =  filp_open (output_file,  O_WRONLY|O_CREAT, 0);
	fileSize  =   (unsigned int)in_filp->f_path.dentry->d_inode->i_size;

	if (fileSize > 20000)  {
		printk (KERN_ERR "Filesize not supported\n");
		returnVal  =  -EINVAL;
		goto out;
	}

	buf  =  kzalloc (fileSize+1,  GFP_KERNEL);
	dst  =  kzalloc (fileSize+1,  GFP_KERNEL);

	if (!in_filp || IS_ERR(in_filp))  {
		printk (KERN_ERR "Unable to open the input file to compute the checksum");
		returnVal  =  PTR_ERR (in_filp);
		in_filp  =  NULL;
		goto out;
	}
	if (!in_filp->f_op->read)  {
		printk (KERN_ERR "Input File does not allow reads!!");
		returnVal  =  PTR_ERR (in_filp);
		in_filp  =  NULL;
		goto out;
	}

	if (!out_filp || IS_ERR(out_filp))  {
		printk (KERN_ERR "Unable to open the input file to compute the checksum");
		returnVal  =  PTR_ERR (out_filp);
		out_filp  =  NULL;
		goto out;
	}
	if (!out_filp->f_op->write)  {
		printk (KERN_ERR "output File does not allow writes!!");
		returnVal  =  PTR_ERR (out_filp);
		out_filp  =  NULL;
		goto out;
	}

	out_filp->f_path.dentry->d_inode->i_mode =  in_filp->f_path.dentry->d_inode->i_mode;

	in_filp->f_pos  =  0;
	oldfs  =  get_fs ();
	set_fs (KERNEL_DS);

	no_of_bytes_read  =  in_filp->f_op->read (in_filp,   buf, fileSize, &in_filp->f_pos);
	if (no_of_bytes_read < 0)  {
		returnVal  =  -EINVAL;
		printk (KERN_ERR "Error: initializing the transformation object\n");
		goto out;

	}

	tfm  =  crypto_alloc_comp ("deflate",  0, 0);

	if (!tfm)  {
		returnVal  =  -EINVAL;
		printk (KERN_ERR "Error: initializing the transformation object\n");
		goto out;
	}

	returnVal  =  crypto_comp_compress (tfm,   (char *)buf, fileSize, (char *)dst, &dst_len);

	if (returnVal < 0)  {
		returnVal  =  -EINVAL;
		printk (KERN_ERR "Error: Compression failed\n");
		goto out;
	}
	no_of_bytes_written  =  out_filp->f_op->write (out_filp,   dst, dst_len, &out_filp->f_pos);
	if (no_of_bytes_written < 0)  {
		returnVal  =  -EINVAL;
		printk (KERN_ERR "Error: initializing the transformation object\n");
		goto out;

	}
out:
	return returnVal;
}

int functionToDecompress (char *input_file,  char *output_file)
 {

	struct file *in_filp  =  NULL;
	struct file *out_filp  =  NULL;
	mm_segment_t oldfs;
	int no_of_bytes_read  =  0;
	int no_of_bytes_written  = 0;
	int dst_len ;
	int returnVal  =  0;
	int fileSize  =  0;
	void *buf  =  NULL;
	char *dst  =  NULL;
	struct crypto_comp *tfm;

	in_filp  =  filp_open (input_file,  O_RDONLY, 0);
	out_filp  =  filp_open (output_file,  O_WRONLY|O_CREAT, 0);
	fileSize  =   (unsigned int)in_filp->f_path.dentry->d_inode->i_size;
	buf  =  kzalloc (fileSize+1,  GFP_KERNEL);
	dst  =  kzalloc (fileSize+1,  GFP_KERNEL);

	if (!in_filp || IS_ERR(in_filp))  {
		printk (KERN_ERR "Unable to open the input file to compute the checksum");
		returnVal  =  PTR_ERR (in_filp);
		in_filp  =  NULL;
		goto out;
	}
	if (!in_filp->f_op->read)  {
		printk (KERN_ERR "Input File does not allow reads!!");
		returnVal  =  PTR_ERR (in_filp);
		in_filp  =  NULL;
		goto out;
	}

	if (!out_filp || IS_ERR(out_filp))  {
		printk (KERN_ERR "Unable to open the input file to compute the checksum");
		returnVal  =  PTR_ERR (out_filp);
		out_filp  =  NULL;
		goto out;
	}
	if (!out_filp->f_op->write)  {
		printk (KERN_ERR "output File does not allow writes!!\n");
		returnVal  =  PTR_ERR (out_filp);
		out_filp  =  NULL;
		goto out;
	}

	out_filp->f_path.dentry->d_inode->i_mode =  in_filp->f_path.dentry->d_inode->i_mode;

	in_filp->f_pos  =  0;
	oldfs  =  get_fs ();
	set_fs (KERNEL_DS);

	no_of_bytes_read  =  in_filp->f_op->read (in_filp,   buf, fileSize, &in_filp->f_pos);
	if (no_of_bytes_read < 0)  {
		returnVal  =  -EINVAL;
		printk (KERN_ERR "Error: initializing the transformation object\n");
		goto out;

	}

	tfm  =  crypto_alloc_comp ("deflate",  0, 0);

	if (!tfm)  {
		returnVal  =  -EINVAL;
		printk (KERN_ERR "Error: initializing the transformation object\n");
		goto out;
	}

	returnVal  =  crypto_comp_decompress (tfm,   (char *)buf, fileSize, (char *)dst, &dst_len);

	if (returnVal < 0)  {
		returnVal  =  -EINVAL;
		printk (KERN_ERR "Error: Compression failed\n");
		goto out;
	}
	no_of_bytes_written  =  out_filp->f_op->write (out_filp,   dst, dst_len, &out_filp->f_pos);
	if (no_of_bytes_written < 0)  {
		returnVal  =  -EINVAL;
		printk (KERN_ERR "Error: initializing the transformation object\n");
		goto out;

	}
out:
	return returnVal;

}


int actionPerformed (const void *key,   int key_len, void *bufTemp, int *bytesRead,
		const void *buf,   size_t src_len, int action) {

	long ret = 0;

	switch (action)  {

		case ENCRYPTION:
			ret = functionToEncrypt (key,   key_len, bufTemp, bytesRead, buf, src_len);
			if (ret < 0)
				goto out;

			break;

		case DECRYPTION:
			ret = functionToDecrypt (key,   key_len, bufTemp, bytesRead, buf, src_len);
			if (ret < 0)
				goto out;

			break;

	}

out:
	return ret;
}

int performAction (char *infile,   char *outfile, char *keybuf, int action)
 {
	long ret = 0;
	int bytesRead;
	int bytesWrite;
	unsigned int fileSize  =  0;
	unsigned int numberOfPageSize  =  0;
	unsigned int countPage = 0;
	struct file *filpr;
	struct file *filpw;
	char *buf = NULL;
	char *bufTemp = NULL;
	mm_segment_t oldfs;

	struct crypto_shash *md5;
	char *md5_hash  =  NULL;
	struct shash_desc *desc;
	int cryptSize;

	buf =   (char *) kmalloc(PAGE_SIZE,   GFP_KERNEL);
	if (buf   ==  NULL)  {
		ret = -ENOMEM;
		goto out;
	}

	memset (buf,   0, PAGE_SIZE);
	bufTemp =   (char *) kmalloc(PAGE_SIZE,   GFP_KERNEL);

	if (bufTemp   ==  NULL)  {
		ret = -ENOMEM;
		goto out;
	}

	memset (bufTemp,   0, PAGE_SIZE);

	filpr  =  filp_open (infile,   O_RDONLY, 0);
	if (!filpr || IS_ERR(filpr))  {
		ret  =  -ENOENT;
		goto out;
	}

	if  (!filpr->f_op->read)  {
		ret  =  -EIO;
		goto out;
	}
	if (!S_ISREG(filpr->f_path.dentry->d_inode->i_mode))  {
		ret  =  -EBADF;
		goto out;
	}

	filpw =  filp_open (outfile,   O_WRONLY|O_CREAT|O_TRUNC, 0);
	if (!filpw || IS_ERR(filpw))  {
		ret  =  -ENOENT;
		goto out;
	}
	if  (!filpw->f_op->write)  {
		ret  =  -EIO;
		goto out;
	}
	if (!S_ISREG(filpw->f_path.dentry->d_inode->i_mode))  {
		ret  =  -EBADF;
		goto out;
	}

	filpw->f_path.dentry->d_inode->i_mode =  filpr->f_path.dentry->d_inode->i_mode;

	oldfs  =  get_fs ();
	set_fs (KERNEL_DS);

	fileSize  =   (unsigned int)filpr->f_path.dentry->d_inode->i_size;
	numberOfPageSize = fileSize/PAGE_SIZE;

	if (action  == ENCRYPTION || action == DECRYPTION) {

		md5  =  crypto_alloc_shash ("md5",   0, 0);
		if  (md5   ==  NULL)  {
			ret  =  -ENOMEM;
			goto out;
		}

		cryptSize  =  sizeof (struct shash_desc) + crypto_shash_descsize(md5);
		desc  =  kmalloc (cryptSize,   GFP_KERNEL);
		if  (!desc)  {
			ret  =  -ENOMEM;
			goto out;
		}
		memset (desc,   0, cryptSize);

		md5_hash  =  kmalloc (AES_BLOCK_SIZE,   GFP_KERNEL);
		if  (!md5_hash)  {
			ret  =  -ENOMEM;
			goto out;
		}
		memset (md5_hash,   0, AES_BLOCK_SIZE);

		desc->tfm  =  md5;
		desc->flags  =  0x0;

		ret  =  crypto_shash_digest (desc,  (const char *)keybuf, AES_BLOCK_SIZE, md5_hash);
		if  (ret) {
			ret  =  -EINVAL;
			goto out;
		}

		crypto_free_shash (md5);
	}

	if (fileSize > 0)  {
		filpw->f_pos  =  0;

		if (action  == ENCRYPTION)
			bytesWrite  =  filpw->f_op->write (filpw,   md5_hash, AES_BLOCK_SIZE, &filpw->f_pos);
		else if (action  == DECRYPTION)  {
			bytesRead  =  filpr->f_op->read (filpr,   buf, AES_BLOCK_SIZE, &filpr->f_pos);
			if  (memcmp(md5_hash,   buf, AES_BLOCK_SIZE) !=  0) {

				vfs_unlink (filpw->f_path.dentry->d_parent->d_inode,   filpw->f_path.dentry, NULL);

				ret  =  -EINVAL;
				goto out;
			}
		}

		memset (buf,   0, PAGE_SIZE);
		memset (bufTemp,   0, PAGE_SIZE);

		while (numberOfPageSize > 0)  {
			bytesRead  =  filpr->f_op->read (filpr,   buf, PAGE_SIZE, &filpr->f_pos);
			if (bytesRead < 0) {
				ret = -EIO;
				goto out;
			}

			ret  =  actionPerformed (keybuf,   AES_BLOCK_SIZE, bufTemp, &bytesRead, buf, PAGE_SIZE, action);
			if (ret)  {
				ret  =  -EINVAL;
				goto out;
			}

			bytesWrite  =  filpw->f_op->write (filpw,   bufTemp, PAGE_SIZE, &filpw->f_pos);

			if (bytesWrite < 0)  {
				ret = -EIO;
				goto out;
			}

			memset (buf,   0, PAGE_SIZE);
			memset (bufTemp,   0, PAGE_SIZE);
			numberOfPageSize = numberOfPageSize-1;
			countPage = countPage+1;
		}

		fileSize = fileSize - (countPage*PAGE_SIZE);

		if (fileSize > 0)  {

			bytesRead  =  filpr->f_op->read (filpr,   buf, fileSize, &filpr->f_pos);
			if (bytesRead < 0)  {
				ret = -EIO;
				goto out;
			}

			ret =  actionPerformed (keybuf,   AES_BLOCK_SIZE, bufTemp, &bytesRead, buf, bytesRead, action);

			if (action  == ENCRYPTION || action == DECRYPTION)
				bytesWrite  =  filpw->f_op->write (filpw,   bufTemp, bytesRead, &filpw->f_pos);
			else
				bytesWrite  =  filpw->f_op->write (filpw,   bufTemp, strlen(bufTemp), &filpw->f_pos);

			if (bytesWrite < 0)  {
				ret = -EIO;
				goto out;
			}
		}

		memset (buf,   0, PAGE_SIZE);
		memset (bufTemp,   0, PAGE_SIZE);
	}

	filp_close (filpw,   NULL);
	filp_close (filpr,   NULL);


out:
	kfree (buf);
	kfree (bufTemp);
	return ret;
}

int performActionByJob (jobs *job)
 {
	int err  =  0;

	if (job->jobtype   ==  ENCRYPTION || job->jobtype == DECRYPTION)  {
		err  =  performAction (job->infile,  job->outfile, job->cipher, job->jobtype);
		if (err)  {
			err  =  -EINVAL;
			goto out;
		}
	}
	else if (job->jobtype   ==  CHECKSUM || job->jobtype == COMPRESS
			|| job->jobtype   ==  DECOMPRESS)  {
		switch (job->jobtype)  {
			case COMPRESS:
				err = functionToCompress (job->infile,  job->outfile);
				if (err < 0)  {
					err  =  -EINVAL;
					goto out;
				}
				break;

			case DECOMPRESS:
				err = functionToDecompress (job->infile,  job->outfile);
				if (err < 0)  {
					err  =  -EINVAL;
					goto out;
				}
				break;

			case CHECKSUM:

				switch (job->algoType)  {
					case MD5_ALGO:
						err  =  functiontoPerformMD5CheckSum (job->infile,  job->outfile);
						if (err < 0)  {
							err  =  -EINVAL;
							goto out;
						}
						break;

					case SHA_ALGO:
						err = functiontoPerformSHA1CheckSum (job->infile,  job->outfile);
						if (err < 0)  {
							err  =  -EINVAL;
							goto out;
						}
						break;

					default:
						err  =  -EINVAL;
						goto out;
				}
		}
	}

	return 0;

out:
	return err;
}



MODULE_LICENSE ("GPL");
MODULE_DESCRIPTION ("File for submitting the system call to the kernel");
MODULE_AUTHOR ("VINAYAK/SOMESH/MANSI/ALPIT");
MODULE_ALIAS ("test");
