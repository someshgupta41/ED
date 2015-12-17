/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

// the common header for the AMFS
#include "amfs.h"
// the header file defined for ioctl support
#include "amfsctl_header.h"
// the header file for linked-list support
#include <linux/list.h>
#include <asm/uaccess.h>

#define ATTR_MODE       (1 << 0)

// If the version of the patter.db file changes and is different from the current file being scanned,
// Invoke toBeQuarantined.
// This function determines whether a previous file is still bad and needs to be quarantined or not
int toBeQuarantined(struct dentry* dentry, struct super_block *sb)
{

	mm_segment_t oldfs;
	// instantiate a structure object for amfs_sb_info
	struct amfs_sb_info* amfs_sb_info_data = (struct amfs_sb_info *)sb->s_fs_info;
	// initialize a buffer to NULL
	char *badBuff = NULL;
	// placeholder to hold the file version
	int fileVersion = 0 ;
	// placeholder to hold the superblock version
	int sversion = 0 ;
	// error flag
	int err = 0;
	// return value
	int ret = 0 ;

	// flag to be set if the file needs to be quarantined
	int quarantineFlag = 1;
	// file Handler
	struct file* file = NULL;
	// fileName
	char* fileName = NULL;
	int retVal = 0;

	// Get VERSION_NUMBER Xtended attribute of the file to check if it matches with the version of the superblock
	retVal = dentry->d_inode->i_op->getxattr(dentry, VERSION_NUMBER, &fileVersion, sizeof(fileVersion));

	// Get the version of the superblock
	sversion = amfs_sb_info_data->version;

	// Check if the fileVersion and the superblock version match and the Xtended attribute is set for the file
	if (fileVersion ==  sversion && retVal >= 0)
	{
		// if yes, set the quarantine flag
		quarantineFlag = 1;
		goto out;
	}
	else
	{
		//get the fileName 
		fileName = (char*)dentry->d_name.name;
		// initialize the buffer of page size
		badBuff = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!badBuff)
		{
			err = -ENOMEM;
			return err;
		}
		// open the file to be checked for malicious content 
		file = filp_open(fileName, O_RDONLY, 0);
		// if not able to allocate memory, throw error
		if (!file || IS_ERR(file))
		{
			quarantineFlag = -EPERM;
			goto out;
		}
		// check if file supports read operations or has read permissions
		if (!file->f_op->read)
		{
			quarantineFlag = -EPERM;
			goto out;
		}
		//set the context to kernel space
		oldfs = get_fs();
		set_fs(KERNEL_DS);

		//if the read fails due to reading malicious content, the bad file is still bad
		while ((ret = file->f_op->read(file, badBuff, PAGE_SIZE, &file->f_pos)) > 0);

		if (ret < 0)
		{

		//set the quarantineFlag
			quarantineFlag = 1;

		}
		set_fs(oldfs);
	}

	if (quarantineFlag == 0)
	{
		goto out;
	}
out:
	// free the buffers and close the opened file
	if (badBuff)
		kfree(badBuff);
	if (file)
		filp_close(file, NULL);
	return quarantineFlag;

}



static ssize_t amfs_read(struct file *file, char __user *buf,
                         size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	int result = -1;
	//initialize the list-head and pattern variables
	struct list_pattern *curr = NULL;
	struct list_head *pos = NULL;
	//set the mode for CHMOD 000
	umode_t mode = 32768;
	//instantiate a new structure of iattr
	struct iattr newattrs;

	int match = 1;
	int ret = 0;
	char *i = NULL;
	char* newPattern = NULL;
	//instantiate an instance of the amfs_sb_info structure 
	struct amfs_sb_info* amfs_sb_info_data = (struct amfs_sb_info *)dentry->d_inode->i_sb->s_fs_info;
	struct list_head* head = amfs_sb_info_data->first;

	lower_file = amfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
	{
		fsstack_copy_attr_atime(dentry->d_inode,
		                        file_inode(lower_file));

	}

	i = newPattern;
	// iterate over all the elements of the linkedlist
	list_for_each(pos, head)
	{
		// current element of the linked list
		curr = list_entry(pos, struct list_pattern, next_node);
		// to check if a substring of buffer matches with the current element of the linked list
		if (strstr(buf, curr->pattern) != NULL)
		{
			//if it does, set the BAD_FLAG of the file
			result = file->f_path.dentry->d_inode->i_op->setxattr(file->f_path.dentry, BAD_FLAG, &match, sizeof(match), 0);
			//Set the mode attributes of the file
			newattrs.ia_mode = mode;
			newattrs.ia_valid = ATTR_MODE;
			ret = dentry->d_inode->i_op->setattr(dentry, &newattrs);

			//as soon a virus is detected, return OPERATION NOT PERMITTED and abort
			err = -EPERM;
			goto out;

		}

	}

out:
	//free the buffer and return errors,if any
	if (i)
		kfree(i);
	return err;
}

static ssize_t amfs_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	int result = -1;
	int ret = 0;
	int match = 1;
	
	//initialize the list-head and pattern variables
	struct list_pattern *curr = NULL;
	struct list_head *pos = NULL;
	//instantiate a new structure of iattr
	struct iattr newattrs;
	//set the mode for CHMOD 000
	umode_t mode = 32768;
	//instantiate an instance of the amfs_sb_info void* structure 
	struct amfs_sb_info* amfs_sb_info_data = (struct amfs_sb_info *)dentry->d_inode->i_sb->s_fs_info;
	//initialize the head of the list
	struct list_head* head = amfs_sb_info_data->first;
	
	char *t = NULL;
	char* newPattern = NULL;
	char* patt = NULL;


	newPattern = kzalloc(strlen((char*)buf) + 1, GFP_KERNEL);
	if (!newPattern)
	{
		err = -ENOMEM;
		return err;
	}
	err = copy_from_user(newPattern, (char*) buf, strlen_user((char*)buf));
	if (err < 0)
	{
		return err;
	}


	lower_file = amfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
		                        file_inode(lower_file));
		fsstack_copy_attr_times(dentry->d_inode,
		                        file_inode(lower_file));
	}

	// get the BAD_FLAG attribute of the file and return OPERATION NOT PERMITTED if the attribute is SET.
	ret = file->f_path.dentry->d_inode->i_op->getxattr(file->f_path.dentry, BAD_FLAG, &match, sizeof(match));
	if (ret >= 0)
	{
		return -EPERM;
	}

	// initialize the head of new-pattern to be used for freeing the buffer later
	t = newPattern;

	//parse the newPattern buffer and search for a malicious pattern, if present
	while ((patt = strsep(&newPattern, " \n")) != NULL)
	{
		// iterate over all the elements of the linkedlist
		list_for_each(pos, head)
		{
			// current element of the linked list
			curr = list_entry(pos, struct list_pattern, next_node);
			// to check if a substring of buffer matches with the current element of the linked list
			if (strstr(patt, curr->pattern) != NULL)
			{
				//if it does, set the BAD_FLAG of the file
				result = file->f_path.dentry->d_inode->i_op->setxattr(file->f_path.dentry, BAD_FLAG, &match, sizeof(match), 0);
				//Set the mode attributes of the file
				newattrs.ia_mode = mode;
				newattrs.ia_valid = ATTR_MODE;
				ret = file->f_path.dentry->d_inode->i_op->setattr(dentry, &newattrs);
				//as soon a virus is detected, return OPERATION NOT PERMITTED and abort
				return -EPERM;

			}
		}
	}

	if (t)
		kfree(t);
	return err;
}


// The structure used by filldir to iterate over all the elements of the present directory
struct amfs_lookup_structure {
	struct dir_context ctx;
	struct dir_context *caller;
	struct super_block *sb;
	// added a new field for the dentry of the upper F/S
	struct dentry *dentry;
};

static int
amfs_filldir(struct dir_context *ctx, const char *lower_name,
             int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	//instantiate a qstr object to be populated later
	struct qstr this;
	//instantiate a dentry for the lower_fs
	struct dentry *lower_dentry;
	//place holder for the BAD_FLAG extended attribute
	int values = 0;
	int k;
	int retVal = 0;
	int quarantineFlag = 0;
	
	// instantiate a object of the amfs_lookup structure
	struct amfs_lookup_structure *buf =
	    container_of(ctx, struct amfs_lookup_structure, ctx);

	// instantiate a object of the amfs_lookup structure
	// with name as lower_name and len as lower_namelen
	this.name = lower_name;
	this.len = strlen(lower_name);
	this.hash = full_name_hash(this.name, this.len);
	// get the lower dentry of the file from the upper one
	lower_dentry = d_lookup(buf->dentry, &this);


	if (!lower_dentry)
		goto emit;

	//check if the attribute is set for BAD_FLAG
	retVal =  lower_dentry->d_inode->i_op->getxattr(lower_dentry, BAD_FLAG, &values, sizeof(values));

	// if the extended attribute is set for the BAD_FLAG, then check if the file needs to be quarantined, because of some 
	// version change to the patternDb
	if (values == 1)
	{
		//check if the file is to be Quarantined or not
		quarantineFlag = toBeQuarantined(lower_dentry, buf->sb);
		// if the file is clean, then remove the xattr from the file
		if (quarantineFlag == 0)
		{
			retVal = lower_dentry->d_inode->i_op->removexattr(lower_dentry, BAD_FLAG);
		}
	}

	// get the extended attribute of the lower_dentry to determine whether to show/hide them in lookup
	k = lower_dentry->d_inode->i_op->getxattr(lower_dentry, BAD_FLAG, &values, sizeof(values));
	if (k < 0)
	{
		printk("\nThis %s clean file!!\n", lower_dentry->d_name.name);
	}
	else
	{
		// if the file is malicious, return from the function without listing the file
		printk("\nThis %s is a malicious file!!\n", lower_dentry->d_name.name);
		retVal = 0;
		goto out;
	}

	retVal = 0;

emit:
	//display the clean files 
	buf->caller->pos = buf->ctx.pos;
	retVal = !dir_emit(buf->caller, lower_name, lower_namelen, ino, d_type);

out:
	return retVal;
}

/**
 amfs_readdir - displays the files present in a directory
@file: The amfs directory file
@ctx: The actor to feed the entries to
*/
static int amfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;

	struct dentry *dentry = file->f_path.dentry;

	// populate the amfs_lookup_structure to be used by amfs_filldir()
	struct amfs_lookup_structure buf = {
		.ctx.actor = amfs_filldir,
		.caller = ctx,
		.sb = dentry->d_sb,
	};
	lower_file = amfs_lower_file(file);
	buf.dentry = lower_file->f_path.dentry;
	err = iterate_dir(lower_file, &buf.ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
		                        file_inode(lower_file));
	return err;
}

// define the behaviour for the ioctl used for adding/deleting/removing patterns to/from the patternDb
static long amfs_unlocked_ioctl(struct file *file, unsigned int cmd,
                                unsigned long arg)
{
	mm_segment_t oldfs;
	int bytes = 0;
	int err = 0;
	int flag = 0 ;
	int v = 0;
	char *buffer = NULL;
	char *rbuffer = NULL;
	int found = 0;
	int newFileCreate = 0;
	int removeFlag = 0;
	struct amfs_sb_info* amfs_sb_info_data = (struct amfs_sb_info *)file->f_path.dentry->d_inode->i_sb->s_fs_info;
	struct file *fileHandler = NULL;


	char c = '\n';
	struct list_pattern *curr = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	struct list_pattern *list_iterate = NULL;

	rbuffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
	buffer = kzalloc(strlen((char*)arg) + 1, GFP_KERNEL);
	if (!buffer)
	{
		err = -ENOMEM;
		return err;
	}
	err = copy_from_user(buffer, (char*) arg, strlen_user((char*)arg));
	if (err < 0)
	{
		err = -EPERM;
		return err;
	}
	buffer[strlen_user((char*)(arg))] = '\0';
	switch (cmd)
	{
	case ADD_IOCTL:
		fileHandler = filp_open((char *)amfs_sb_info_data->pattern_db, O_WRONLY | O_APPEND, 0);
		if (!fileHandler || IS_ERR(fileHandler)) {
			printk("error while opening file \n");
			return -1;
		}

		if (!fileHandler->f_op->write)
		{
			printk("error while opening file \n");
			return -2;
		}

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		//check if the pattern already exists in the file, if yes, don't add the pattern to the file
		list_for_each_safe(pos, n, amfs_sb_info_data->first)
		{
			curr = list_entry(pos, struct list_pattern, next_node);

			if (strcmp(curr->pattern, buffer) == 0)
			{
				found = 1;
				err = -EEXIST;
				return err;
			}

		}
		//Add pattern to the add the end of the list 
		list_iterate = kzalloc(sizeof(struct list_pattern), GFP_KERNEL);
		list_iterate->pattern = kzalloc(sizeof(buffer), GFP_KERNEL);
		memcpy(list_iterate->pattern, buffer, sizeof(buffer));
		INIT_LIST_HEAD(&list_iterate->next_node);
		list_add(&(list_iterate->next_node), amfs_sb_info_data->first);

		//write the buffer to the patternDb file
		bytes = fileHandler->f_op->write(fileHandler, buffer, strlen(buffer), &fileHandler->f_pos);
		// as the patternDb file is delimited by '\n', append one after each addition
		bytes = fileHandler->f_op->write(fileHandler, &c, sizeof(c), &fileHandler->f_pos);
		if (bytes < 0)
		{
			return -1;
		}
		// after successful append , update the version number of the patternDb file 
		fileHandler->f_path.dentry->d_inode->i_op->getxattr(fileHandler->f_path.dentry, VERSION_NUMBER, &v, sizeof(v));
		//increment the version number by one
		v++;
		//store the version number calculated in the version_number field of the patternDb
		flag = fileHandler->f_path.dentry->d_inode->i_op->setxattr(fileHandler->f_path.dentry, VERSION_NUMBER, &v, sizeof(v), 0);
		if (flag < 0)
		{
			return -EPERM;
		}
		//store the same version in the superblock's version as well 
		amfs_sb_info_data->version = v;
		set_fs(oldfs);
		if (fileHandler)
			filp_close(fileHandler, NULL);

		return 0;

	case REMOVE_IOCTL:

		//check if the pattern already exists in the file, if yes, new file is created with that pattern removed
		list_for_each_safe(pos, n, amfs_sb_info_data->first)
		{
			curr = list_entry(pos, struct list_pattern, next_node);

			if (strcmp(curr->pattern, buffer) == 0)
			{
				list_del(pos);
				newFileCreate = 1;
			}

		}
		//return, if the pattern does not exist
		if (newFileCreate == 0)
		{
			err = -ENOMSG;
			goto out;
		}

		fileHandler = filp_open((char *)amfs_sb_info_data->pattern_db, O_TRUNC, 0);
		if (!fileHandler || IS_ERR(fileHandler)) {
			return -1;
		}

		if (!fileHandler->f_op->write)
		{
			return -2;
		}

		oldfs = get_fs();
		set_fs(KERNEL_DS);

		//add the remaining patterns to the patternDb File
		list_for_each_safe(pos, n, amfs_sb_info_data->first)
		{
			curr = list_entry(pos, struct list_pattern, next_node);
			bytes = fileHandler->f_op->write(fileHandler, curr->pattern, strlen(curr->pattern), &fileHandler->f_pos);
			bytes = fileHandler->f_op->write(fileHandler, &c, sizeof(c), &fileHandler->f_pos);
			if (bytes < 0)
			{
				return -1;
			}

		}
		// after successful append , update the version number of the patternDb file 
		fileHandler->f_path.dentry->d_inode->i_op->getxattr(fileHandler->f_path.dentry, VERSION_NUMBER, &v, sizeof(v));
		//increment the version number by one
		v++;
		//store the version number calculated in the version_number field of the patternDb
		removeFlag = fileHandler->f_path.dentry->d_inode->i_op->setxattr(fileHandler->f_path.dentry, VERSION_NUMBER, &v, sizeof(v), 0);
		if (removeFlag < 0)
		{
			return -EPERM;
		}
		//store the same version in the superblock's version as well 
		amfs_sb_info_data->version = v;
		set_fs(oldfs);
		if (fileHandler)
			filp_close(fileHandler, NULL);

		return 0;


	case LIST_IOCTL:
		fileHandler = filp_open((char *)amfs_sb_info_data->pattern_db, O_RDONLY, 0);
		if (!fileHandler || IS_ERR(fileHandler)) {
			return -1;
		}

		if (!fileHandler->f_op->read)
		{
			return -2;
		}

		rbuffer = (char *)kzalloc(PAGE_SIZE, GFP_KERNEL);

		fileHandler->f_pos = 0;
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		// return, if error 
		// otherwise add the list of patterns to the rbuffer
		bytes = fileHandler->f_op->read(fileHandler, rbuffer, PAGE_SIZE, &fileHandler->f_pos);

		if (bytes < 0)
		{
			err = -EFAULT;
			goto out;
		}

		//copy the rbuffer populated to the console for displaying
		err = copy_to_user((char*) arg, rbuffer, strlen_user((char*)rbuffer));
		if (err < 0)
		{
			err = -EPERM;
			return err;
		}

		set_fs(oldfs);
		if (fileHandler)
			filp_close(fileHandler, NULL);

		return 0;
	}

	return 0;
out:
	if (!fileHandler)
		filp_close(fileHandler, NULL);
	return err;
}

#ifdef CONFIG_COMPAT
static long amfs_compat_ioctl(struct file *file, unsigned int cmd,
                              unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = amfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int amfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = amfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "amfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!AMFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "amfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &amfs_vm_ops;

	file->f_mapping->a_ops = &amfs_aops; /* set our aops */
	if (!AMFS_F(file)->lower_vm_ops) /* save for our ->fault */
		AMFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int amfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;
	int superblock_version ;
	int returnVal = 0;
	int version = 0;
	int ans = 0;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}


	file->private_data = kzalloc(sizeof(struct amfs_file_info), GFP_KERNEL);


	if (!AMFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	superblock_version  =  ((struct amfs_sb_info*)(file->f_path.dentry->d_sb->s_fs_info))->version;
	returnVal = file->f_path.dentry->d_inode->i_op->getxattr(file->f_path.dentry, VERSION_NUMBER, &version, sizeof(version));
	if (returnVal < 0)
	{
		ans = file->f_path.dentry->d_inode->i_op->setxattr(file->f_path.dentry, VERSION_NUMBER, &version, sizeof(version), 0);
		if (ans < 0)
		{
			return -EPERM;
		}
	}
	/* open lower object and link amfs's file struct to lower's */
	amfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = amfs_lower_file(file);
		if (lower_file) {
			amfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		amfs_set_lower_file(file, lower_file);
	}
	if (err)
		kfree(AMFS_F(file));
	else
		fsstack_copy_attr_all(inode, amfs_lower_inode(inode));
out_err:
	return err;
}

static int amfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	int returnVal = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct amfs_sb_info* amfs_sb_info_data = (struct amfs_sb_info *)dentry->d_inode->i_sb->s_fs_info;
	int sb_ka_version = amfs_sb_info_data -> version;

	lower_file = amfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	returnVal = file->f_path.dentry->d_inode->i_op->setxattr(file->f_path.dentry, VERSION_NUMBER, &sb_ka_version, sizeof(sb_ka_version), 0);
	if (returnVal < 0)
	{
		err = -EPERM;
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int amfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = amfs_lower_file(file);
	if (lower_file) {
		amfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(AMFS_F(file));
	return 0;
}

static int amfs_fsync(struct file *file, loff_t start, loff_t end,
                      int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = amfs_lower_file(file);
	amfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	amfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int amfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = amfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

static ssize_t amfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
                             unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_read)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
		                        file_inode(lower_file));
out:
	return err;
}

static ssize_t amfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
                              unsigned long nr_segs, loff_t pos)
{
	int err = -EINVAL;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->aio_write)
		goto out;
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
		                        file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
		                        file_inode(lower_file));
	}
out:
	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t amfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = amfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Wrapfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
amfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
		                        file_inode(lower_file));
out:
	return err;
}

/*
 * Wrapfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
amfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = amfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
		                        file_inode(lower_file));
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
		                        file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations amfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= amfs_read,
	.write		= amfs_write,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.mmap		= amfs_mmap,
	.open		= amfs_open,
	.flush		= amfs_flush,
	.release	= amfs_file_release,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
	.aio_read	= amfs_aio_read,
	.aio_write	= amfs_aio_write,
	.read_iter	= amfs_read_iter,
	.write_iter	= amfs_write_iter,
};

/* trimmed directory options */
const struct file_operations amfs_dir_fops = {
	.llseek		= amfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= amfs_readdir,
	.unlocked_ioctl	= amfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= amfs_compat_ioctl,
#endif
	.open		= amfs_open,
	.release	= amfs_file_release,
	.flush		= amfs_flush,
	.fsync		= amfs_fsync,
	.fasync		= amfs_fasync,
};

