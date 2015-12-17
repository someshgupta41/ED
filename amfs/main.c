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

#include "amfs.h"
#include <linux/module.h>
#include <linux/list.h>

static LIST_HEAD(headstart);

// Function to basically tokenize the raw_data received from the mount command
// to get the fileName for the patternDb
//All possible validations have been performed detailed in README
char* tokenize(char* raw_data){
char *token1, *token2;
const char* delim;

int err=0;
delim = "=";
	if(raw_data ==  NULL)
	{
		err = -ENOENT;
		goto out;
	}
if(strcmp(raw_data,"pattdb=")==0)
{
	err = -EINVAL;
	goto out;

}

	if(strstr(raw_data,delim) == NULL)
	{
		err = -EINVAL;
		goto out;
	}

	token1 = strsep(&raw_data, "=");

	if(strcmp(token1,"pattdb")!=0)
	{
		err = -EINVAL;
		goto out;
	}
	
	token2 = strsep(&raw_data, "=");
	return token2;
	out:
	return ERR_PTR(err);
}


/*
 * There is no need to lock the amfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int amfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	struct super_block *lower_sb;
	struct path lower_path;
	struct inode *inode;
	char * PatternFile; 
	struct amfs_sb_info* amfs_sb_info_data;
	mm_segment_t oldfs;
    int bytes;
    struct list_head *head;
	

	int err = 0;
	int version = 0;
	struct file *filp=NULL;
    int getVersion =0 ;
    char *buf;
    int c_version = 0;
   	struct amfs_opt_data* amfs_patt;
	char *device_name=NULL;
	struct list_pattern *curr;
	struct list_pattern *e=NULL;
	char *line = NULL;
	long f_size=0;
	long numberOfPageSize=0;
    
	amfs_patt=(struct amfs_opt_data*)raw_data;
	device_name = (char *)amfs_patt->device_name;
	
	if (!device_name) {
		printk(KERN_ERR
		       "device_name argument missing\n");
		err = -EINVAL;
		goto out;
	}
	/* parse lower path */
	err = kern_path(device_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"error accessing the lower directory '%s'\n", device_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct amfs_sb_info), GFP_KERNEL);
	if (!AMFS_SB(sb)) {
		printk(KERN_CRIT "Not enough memory\n");
		err = -ENOMEM;
		goto out_free;
	}


	PatternFile= (char *)amfs_patt->pattern_file;
	buf=(char *)kzalloc(PAGE_SIZE, GFP_KERNEL);
    filp = filp_open(PatternFile, O_RDONLY, 0);

    if (!filp || IS_ERR(filp)) {
		return -1;  
    }

    if (!filp->f_op->read)
		return -2;  

	bytes = filp->f_op->read(filp, buf, PAGE_SIZE, &filp->f_pos);

	if(bytes < 0)
	{
		err = -EPERM;
		goto out;
	}
		    
	filp->f_pos = 0;		
    oldfs = get_fs();
    set_fs(KERNEL_DS);


    // calculation of input file size
    f_size = (unsigned int)filp->f_path.dentry->d_inode->i_size;

    // Integral number of PAGE_SIZE out of total file size
    numberOfPageSize=(f_size/PAGE_SIZE)+1;

    //Support for reading more than one page
    while(numberOfPageSize>0)
    {
		    bytes = filp->f_op->read(filp, buf, PAGE_SIZE, &filp->f_pos);
		    set_fs(oldfs);

		    while((line = strsep(&buf,"\n\0"))!=NULL)
			{
				if(strcmp(line,"")==0)
					continue;
				e = kzalloc(sizeof(struct amfs_opt_data), GFP_KERNEL);
				e->pattern = line;
				list_add(&(e->next_node),&headstart);
			}

		numberOfPageSize--;	
	}
//get the version of the patternDb file,
// if set update that otherwise set it to zero
getVersion = filp->f_path.dentry->d_inode->i_op->getxattr(filp->f_path.dentry, VERSION_NUMBER, &version, sizeof(version));
	if(getVersion >=0)
	{
		c_version = version;
	}
	else
	{
		c_version = 0;
	}
    list_for_each(head, &headstart)
	{
	    curr = list_entry(head,struct list_pattern,next_node);

	}

   	
   	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	amfs_sb_info_data=(struct amfs_sb_info *)sb->s_fs_info;
		
	amfs_set_lower_super(sb, lower_sb, amfs_patt->pattern_file,&headstart,c_version);
	
	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &amfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = amfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &amfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	amfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "amfs: mounted on top of %s type %s\n",
		       device_name, lower_sb->s_type->name);
	
	goto out; /* all is well */


	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(AMFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	if(filp)
	filp_close(filp, NULL);
   	if(buf)
   	kfree(buf);
   	return err;
}


struct dentry *amfs_mount(struct file_system_type *fs_type, int flags,
			    const char *device_name, void *raw_data)
{
	long err = 0;
	struct amfs_opt_data* amfs_pat;
	char * raw_data_name;
	struct file* filp=NULL;
	char* fileName = NULL;
	char *pdb=NULL;
	int cnt=0;
	struct iattr newattrs;
	int pattern_name_length=0;
	int nextcnt=0;
	int i=0;
	const char* delim = "=";
	umode_t mode = 32768;
		
	//convert raw_data to string
	raw_data_name=(char *) raw_data; 
	if(raw_data_name == NULL)
	{
		err = -ENOENT;
		goto out;
	}
	//check if the raw_data contains "="
	if(strstr(raw_data_name,delim)==NULL)
	{
		err = -ENOENT;
		goto out;
	}
	//calculate the length of pattdb
	while(*raw_data_name == '=')
	{
			cnt++;
			raw_data_name++;
	}
	
	pattern_name_length=strlen(raw_data_name)-cnt;
	
	pdb = (char *)kzalloc(pattern_name_length*sizeof(char), GFP_KERNEL);
	
	while(*raw_data_name != '\0')
	{
		if(nextcnt>=cnt)
		{
			pdb[i++]=*raw_data_name;
		}
		nextcnt++;
		raw_data_name++;
	}
	
	amfs_pat=(struct amfs_opt_data* )kzalloc(sizeof(struct amfs_opt_data), GFP_KERNEL);
	if (!amfs_pat) 
    {
    
    	printk("error occured while kmalloc");
    }
    
    amfs_pat->device_name = (void *) device_name;
    //get the fileName from the rawData
    fileName = tokenize(pdb);
    //Handle errors if fileName is null or any other error
    if(fileName == NULL || IS_ERR(fileName))
    {
    	printk("error in mounting the fs\n !! ");
    	err = -EPERM;
    	goto out;
    }
    amfs_pat->pattern_file=fileName;
	
	if(fileName == NULL)
	{
		
		err= -EFAULT;
		goto out;
	}
	
	filp = filp_open(fileName, O_WRONLY, 0);
	if(!filp)
	{
		err= -EFAULT;
		goto out;
	}
	//set the mode for the patternDb file to be chmod 000 to prevent unauthorized access
	newattrs.ia_mode = mode;
	newattrs.ia_valid = ATTR_MODE;
	filp->f_path.dentry->d_inode->i_op->setattr(filp->f_path.dentry,&newattrs);
	return mount_nodev(fs_type, flags, amfs_pat,
			   amfs_read_super);
	out:
	if(filp)
	filp_close(filp,NULL);
	return ERR_PTR(err);
	
}

static struct file_system_type amfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= AMFS_NAME,
	.mount		= amfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(AMFS_NAME);

static int __init init_amfs_fs(void)
{
	int err;

	pr_info("Registering amfs " AMFS_VERSION "\n");

	err = amfs_init_inode_cache();
	if (err)
		goto out;
	err = amfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&amfs_fs_type);
out:
	if (err) {
		amfs_destroy_inode_cache();
		amfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_amfs_fs(void)
{
	amfs_destroy_inode_cache();
	amfs_destroy_dentry_cache();
	unregister_filesystem(&amfs_fs_type);
	pr_info("Completed amfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("AMFS " AMFS_VERSION
		   " (http://amfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_amfs_fs);
module_exit(exit_amfs_fs);
