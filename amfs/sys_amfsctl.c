#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "amfsctl_header.h"

#define MAGIC_NUMBER 1234
#define LIST_IOCTL _IOR(MAGIC_NUMBER, 0, int)
#define ADD_IOCTL _IOW(MAGIC_NUMBER,1,int)
#define REMOVE_IOCTL _IOW(MAGIC_NUMBER, 2, int)
#define IOCTL_HELLO _IO(MAGIC_NUMBER,3)

static int Major; 
static char msg[200];

struct cdev *kernel_cdev;
/*static ssize_t amfsctl_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset)
{
  	return simple_read_from_buffer(buffer, length, offset, msg, 200);
}


static ssize_t amfsctl_write(struct file *filp, const char __user *buff, size_t len, loff_t *off)
{
	if (len > 199)
		return -EINVAL;
	int g=0;
	g= copy_from_user(msg, buff, len);
	if(g!=0)
	{
		printk("Copy from User error !!");
		return -EPERM;
	}
	msg[len] = '\0';
	return len;
}
char buf[200];

int amfsctl_ioctl(struct inode *inode, struct file *filep, unsigned int cmd, unsigned long arg) {
	int len = 200;
	int g=0;
	switch(cmd) {
	case ADD_IOCTL:	
	
	g=copy_to_user((char *)arg, buf, 200);
	if(g!=0)
	{
		printk("Copy from User error !!");
		return -EPERM;
	}
		break;
	
	case REMOVE_IOCTL:
	g=copy_from_user(buf, (char *)arg, len);
	if(g!=0)
	{
		printk("Copy from User error !!");
		return -EPERM;
	}
	
		break;

	default:
		return -ENOTTY;
	}
	return len;

}
*/
int open(struct inode *inode, struct file *filp)
{
 
 printk(KERN_INFO "Inside open \n");
 return 0;
}

int release(struct inode *inode, struct file *filp) {
 printk (KERN_INFO "Inside close \n");
 return 0;
}

int ioctl_funcs(struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg)
{

int data=10,ret=0;

switch(cmd) {

case IOCTL_HELLO: 
 printk(KERN_INFO "Hello ioctl world");
 break;
 } 
 
return ret;
 
}

struct file_operations fops = {
 open:   open,
 unlocked_ioctl:  ioctl_funcs,
 release: release
};


static int __init my_module_init(void)
{

 int ret;
 dev_t dev_no,dev;

 kernel_cdev = cdev_alloc(); 
  kernel_cdev->ops = &fops;
 kernel_cdev->owner = THIS_MODULE;
 printk (" Inside init module\n");
  ret = alloc_chrdev_region( &dev_no , 0, 1,"char_arr_dev");
    if (ret < 0) {
  printk("Major number allocation is failed\n");
  return ret; 
 }
 
    Major = MAJOR(dev_no);
    dev = MKDEV(Major,0);
 printk (" The major number for your device is %d\n", Major);
 ret = cdev_add( kernel_cdev,dev,1);
 if(ret < 0 ) 
 {
 printk(KERN_INFO "Unable to allocate cdev");
 return ret;
 }

 return 0;}

static void __exit my_module_exit(void)
{
	unregister_chrdev_region(Major, 1);
}  

module_init(my_module_init);
module_exit(my_module_exit);
MODULE_LICENSE("GPL");
