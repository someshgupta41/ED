#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "sys_submitjob.h"
#include "sys_queue.h"
#include "helper_functions.h"

asmlinkage extern long  (*sysptr)(void *arg,    int argslen);

static void netlink_respond_user (int pid,    char *msg)  {

	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	int msg_size;
	int res;

	msg_size = strlen (msg);

	skb_out  =  nlmsg_new (msg_size,   0);

	if (!skb_out) {

		printk (KERN_ERR "Failed to allocate new skb\n");
		return;

	}
	nlh = nlmsg_put (skb_out,   0, 0, NLMSG_DONE,msg_size, 0);

	if (nlh  == NULL)
	 {
		printk (KERN_ERR "NetLink Header is NULL!\n");
	}

	NETLINK_CB (skb_out).dst_group  =  0; /* not in mcast group */
	strncpy (nlmsg_data(nlh),   msg,msg_size);

	res = nlmsg_unicast (nl_sk,   skb_out,pid);

}

int validate_inout_file(char *input_file,    char *output_file)
 {
	int err  =  0;
	struct file *infile,    *outfile;

	infile  =  filp_open (input_file,    O_RDONLY, 0);

	if (!infile || IS_ERR(infile)) {
		err  =  -ENOENT;
		goto exit_point;
	}

	if (!infile->f_op->read) {
		err  =  -EIO;
		goto infile_err;
	}

	if (!S_ISREG(infile->f_path.dentry->d_inode->i_mode)) {
		err  =  -EBADF;
		goto infile_err;
	}

	outfile  =  filp_open (output_file,    O_WRONLY, infile->f_mode);

	if (!outfile || IS_ERR(outfile)) {
		goto infile_err;
	}

	if (!outfile->f_op->write) {
		err  =  -EROFS;
		goto outfile_err;
	}

	if ((infile->f_path.dentry->d_inode->i_sb  == outfile->f_path.dentry->d_inode->i_sb) &&
			 (infile->f_path.dentry->d_inode->i_ino  ==  outfile->f_path.dentry->d_inode->i_ino)) {
		err  =  -EINVAL;
		goto outfile_err;
	}


outfile_err:
	filp_close (outfile,    NULL);
infile_err:
	filp_close (infile,    NULL);
exit_point:
	return err;
}

asmlinkage long submitjob (void *arg,    int argslen)
 {
	int err  =  0;
	jobs *job  =  NULL,    *user_arg, *cur_job;
	struct queue *que;
	struct queue_elem *elem,    *n_elem;
	void *args  =  NULL;
	char *msg  =  NULL,    cmg[10];
	int remv_job_id;

	if (module_exiting) {
		err  =  -EPERM;
		goto out;
	}

	if  (arg  == NULL)  {
		err  =  -EINVAL;
		printk(KERN_ERR "No arguments passed to syscall\n");
		goto out;
	}

	user_arg  =   (jobs *)arg;

	args  =  kzalloc (argslen,    GFP_KERNEL);
	if (!args) {
		err  =  -ENOMEM;
		printk(KERN_ERR "Cannot allocate space for syscall args\n");
		goto out;
	}

	err  =  copy_from_user (args,    user_arg, argslen);
	if (err) {
		err  =  -EFAULT;
		printk(KERN_ERR "Error copying args\n");
		goto out_kfree;
	}

	job  =   (jobs *)args;

	if (job->jobtype < 1 || job->jobtype > 9) {
		err  =  -EINVAL;
		goto out_kfree;
	}

	if (job->jobtype > 0 && job->jobtype < 6) {

		job->infile  =  kzalloc(strlen(user_arg->infile)+1,    GFP_KERNEL);
		if (!job->infile) {
			err  =  -ENOMEM;
			printk(KERN_ERR "Cannot allocate space for syscall args: infile\n");
			goto out_kfree;
		}
		err  =  copy_from_user(job->infile,    user_arg->infile, strlen(user_arg->infile));
		if (err) {
			err  =  -EFAULT;
			printk(KERN_ERR "Error copying args\n");
			goto out_infile;
		}

		job->infile[strlen(user_arg->infile)]  =  '\0';

		job->outfile  =  kzalloc(strlen(user_arg->outfile)+1,    GFP_KERNEL);
		if (!job->outfile) {
			err  =  -ENOMEM;
			printk (KERN_ERR "Cannot allocate space for syscall args: outfile\n");
			goto out_infile;
		}
		err  =  copy_from_user (job->outfile,    user_arg->outfile, strlen(user_arg->outfile));
		if (err) {
			err  =  -EFAULT;
			printk (KERN_ERR "Error copying args\n");
			goto out_outfile;
		}

		job->outfile[strlen (user_arg->outfile)]  =  '\0';

		err  =  validate_inout_file (job->infile,    job->outfile);
		if (err) {
			printk (KERN_ERR "Error in input/output files validation!\n");
			goto out_outfile;
		}
	}

	if (job->jobtype > 0 && job->jobtype < 3) {

		job->cipher  =  kzalloc (user_arg->cipher_len + 1,    GFP_KERNEL);
		if (!job->cipher) {
			err  =  -ENOMEM;
			printk (KERN_ERR "Cannot allocate space for syscall args: cipher\n");
			goto out_outfile;
		}
		err  =  copy_from_user (job->cipher,    user_arg->cipher, user_arg->cipher_len);
		if (err) {
			err  =  -EFAULT;
			printk (KERN_ERR "Error copying args\n");
			goto out_cipher;
		}

		job->cipher[strlen (user_arg->cipher)]  =  '\0';
	}

	msg  =  kzalloc (PAGE_SIZE,    GFP_KERNEL);

	if (!msg) {
		printk (KERN_ERR "Error in allocating memory to msg!\n");
		err  =  -ENOMEM;
	}

	switch (job->jobtype) {
		case LIST:
			elem  =  q_actv->head;
			if (elem  == NULL)
				strcat (msg,   "Queue is empty!\n");
			else {
				strcat (msg,   "Active Queue\n");
				strcat (msg,   "JOB ID  PRIORITY  JOB TYPE\n");
			}

			while (elem) {
				sprintf (cmg,   "%d\t", elem->job->job_id);
				strcat (msg,    cmg);

				memset (cmg,    0, 10);
				sprintf (cmg,   "%d\t", elem->job->priority);
				strcat (msg,    cmg);


				switch (elem->job->jobtype) {
					case CHECKSUM:
						strcat (msg,   "CHECKSUM\n");
						break;
					case ENCRYPTION:
						strcat (msg,   "ENCRYPTION\n");
						break;
					case DECRYPTION:
						strcat (msg,   "DECRYPTION\n");
						break;
					case COMPRESS:
						strcat (msg,   "COMPRESS\n");
						break;
					case DECOMPRESS:
						strcat (msg,   "DECOMPRESS\n");
						break;
				}

				elem  =  elem->next;
			}

			elem  =  q_wait->head;

			if (elem !=  NULL) {
				strcat (msg,   "\nWait Queue\n");
			}

			while (elem) {

				sprintf (cmg,   "%d\t", elem->job->job_id);
				strcat (msg,    cmg);

				memset (cmg,    0, 10);
				sprintf (cmg,   "%d\t", elem->job->priority);
				strcat (msg,    cmg);

				switch (elem->job->jobtype) {
					case CHECKSUM:
						strcat (msg,   "CHECKSUM\n");
						break;
					case ENCRYPTION:
						strcat (msg,   "ENCRYPTION\n");
						break;
					case DECRYPTION:
						strcat (msg,   "DECRYPTION\n");
						break;
					case COMPRESS:
						strcat (msg,   "COMPRESS\n");
						break;
					case DECOMPRESS:
						strcat (msg,   "DECOMPRESS\n");
						break;
				}

				elem  =  elem->next;
			}

			goto out_kfree;

		case REMOVE:
			if (job->job_id < 1 || job->job_id > INT_MAX) {
				printk (KERN_ERR "Invalid job id found in kernel!\n");
				err  =  -EINVAL;
				goto out_kfree;
			}

			mutex_lock (&mutex_len);

			remv_job_id = job->job_id;
			err  =  removeJobByID (q_actv,    job->job_id);
			if (err  == -ENOENT) {
				err  =  removeJobByID (q_wait,    job->job_id);
				if (err < 0) {
					mutex_unlock (&mutex_len);
					sprintf(msg, "Job %d does not exist in queue!", remv_job_id);
					goto out_kfree;
				} else  {
					err  =  0;
					sprintf(msg, "Job %d successfully removed!", remv_job_id);
					q_wait_len--;
				}
			} else if  (!err)  {
				q_actv_len--;
				sprintf(msg, "Job %d successfully removed!", remv_job_id);

				if (q_wait_len > 0) {
					cur_job  =  removeJob (q_wait);
					if (IS_ERR(cur_job)) {
						err  =  PTR_ERR (cur_job);
						mutex_unlock (&mutex_len);
						goto out_kfree;
					}
					que  =  insertJob (q_actv,    cur_job);
					if (IS_ERR(que)) {
						err  =  PTR_ERR (que);
						mutex_unlock (&mutex_len);
						goto out_kfree;
					}
					q_wait_len--;
					q_actv_len++;
				}
			} else  {
				sprintf(msg, "Job %d does not exist in queue!", remv_job_id);
				err  =  0;
			}

			mutex_unlock (&mutex_len);
			goto out_kfree;

		case REMOVE_ALL:
			elem  =  q_actv->head;

			mutex_lock (&mutex_len);
			while (elem)  {

				n_elem  =  elem->next;
				cur_job  =  removeJob (q_actv);
				if (IS_ERR(cur_job)) {
					err  =  PTR_ERR (cur_job);
					mutex_unlock (&mutex_len);
					goto out_kfree;
				}
				else {
					kfree (cur_job);
					q_actv_len--;
				}

				elem  =  n_elem;
			}

			elem  =  q_wait->head;
			while (elem)  {

				n_elem  =  elem->next;
				cur_job  =  removeJob (q_wait);
				if (IS_ERR(cur_job)) {
					err  =  PTR_ERR (cur_job);
					mutex_unlock (&mutex_len);
					goto out_kfree;
				}
				else {
					kfree (cur_job);
					q_wait_len--;
				}

				elem  =  n_elem;
			}
			mutex_unlock (&mutex_len);
			strcat (msg,   "All jobs successfully removed!\n");
			goto out_kfree;
		case PRIORITY_CHANGE:
			if (job->job_id < 1 || job->job_id > INT_MAX) {
				printk (KERN_ERR "Invalid job id provided!\n");
				err  =  -EINVAL;
				goto out_kfree;
			}

			mutex_lock (&mutex_len);
			remv_job_id = job->job_id;
			err  =  changePriorityByID (q_actv,    job->job_id, job->priority);
			if (err  == -ENOENT) {
				err  =  changePriorityByID (q_wait,    job->job_id, job->priority);
				if (err < 0) {
					mutex_unlock (&mutex_len);
					sprintf(msg, "Job %d does not exist in queue!", remv_job_id);
					goto out_kfree;
				} else  {
					err  =  0;
					sprintf(msg, "Job %d priority successfully changed!", remv_job_id);
				}
			} else if  (!err)  {
				sprintf(msg, "Job %d priority successfully changed!", remv_job_id);
			} else  {
				sprintf(msg, "Job %d does not exist in queue!", remv_job_id);
				err  =  0;
			}

			mutex_unlock (&mutex_len);
			goto out_kfree;

	}

	mutex_lock (&mutex_len);
	job_id++;
	job->job_id  =  job_id;
	mutex_unlock (&mutex_len);


restart_producer:
	mutex_lock (&mutex_len);

	if  (q_actv_len < MAX_Q_LEN && job)  {
		que  =  insertJob (q_actv,    job);
		if (IS_ERR(que)) {
			err  =  PTR_ERR (que);
			printk (KERN_ERR "Unable to add job to the active queue\n");
			mutex_unlock (&mutex_len);
			goto out_kfree;
		}
		q_actv_len++;
	} else if  (q_wait_len < MAX_Q_LEN && job)  {
		que  =  insertJob (q_wait,    job);
		if (IS_ERR(que)) {
			err  =  PTR_ERR (que);
			printk (KERN_ERR "Unable to add job to the wait queue\n");
			mutex_unlock (&mutex_len);
			goto out_kfree;
		}
		q_wait_len++;
	} else if  (q_wait_len  == MAX_Q_LEN)  {
		printk (KERN_INFO "Full q: put to sleep\n");
		mutex_unlock (&mutex_len);
		wait_event_interruptible (prod_wq,    q_wait_len < MAX_Q_LEN);
		goto restart_producer;
	}

	mutex_unlock (&mutex_len);
	wake_up_all (&cons_wq);

	goto out;

out_cipher:
	kfree (job->cipher);
out_outfile:
	kfree (job->outfile);
out_infile:
	kfree (job->infile);
out_kfree:
	if (job->jobtype  == LIST || job->jobtype == REMOVE ||
			job->jobtype  == REMOVE_ALL || job->jobtype == PRIORITY_CHANGE)
		err  =  copy_to_user (job->outfile,    msg, strlen(msg));

	if (msg)
		kfree (msg);

	kfree (job);
out:
	return err;
}

int consumer_thread (void *data)
 {
	int err  =  0;
	jobs *cur_job  =  NULL,    *xfr_job = NULL;
	char msg[100];
	struct queue *que;

restart_consumer:
	wait_event_interruptible (cons_wq,    q_actv_len > 0);

	if (module_exiting > 0)
		goto out;

	is_working++;
	mutex_lock (&mutex_len);

	if (q_actv_len > 0) {
		cur_job  =  getHighPriorityJob (q_actv);
		if (IS_ERR(cur_job)) {
			err  =  PTR_ERR (cur_job);
			is_working--;
			mutex_unlock (&mutex_len);
			goto out;
		}
		q_actv_len--;

		if (q_wait_len > 0) {
			xfr_job  =  getHighPriorityJob (q_wait);			
			if (IS_ERR(xfr_job)) {
				err  =  PTR_ERR (xfr_job);
				is_working--;
				mutex_unlock (&mutex_len);
				goto out;
			}

			que  =  insertJob (q_actv,    xfr_job);
			if (IS_ERR(que)) {
				err  =  PTR_ERR (que);
				is_working--;
				mutex_unlock (&mutex_len);
				goto out;
			}

			q_actv_len++;
			q_wait_len--;
		}

	}
	mutex_unlock (&mutex_len);
	wake_up_all (&prod_wq);

	msleep (2000);

	err  =  performActionByJob (cur_job);

	if (err < 0)
		sprintf (msg,   "Job ID: %d could not be completed due to error number : %d ! Please try again...\n", cur_job->job_id, err);
	else
		sprintf (msg,   "Job ID: %d was successfully processed!\n", cur_job->job_id);

	netlink_respond_user (cur_job->pid,    msg);

	kfree (cur_job->infile);
	kfree (cur_job->outfile);

	if (cur_job->cipher !=  NULL)
		kfree (cur_job->cipher);

	kfree (cur_job);
	is_working--;
	schedule ();
	goto restart_consumer;

out:
	return err;

}

static int __init init_sys_submitjob(void)
 {
	printk(KERN_INFO "installed new sys_submitjob module\n");

	q_actv  =  init_queue ();
	if (IS_ERR(q_actv)) {
		return PTR_ERR(q_actv);
	}

	q_wait  =  init_queue();
	if  (IS_ERR(q_wait)) {
		return PTR_ERR(q_wait);
	}

	init_waitqueue_head(&prod_wq);
	init_waitqueue_head(&cons_wq);

	printk(KERN_INFO "Creating NetLink in Kernel!\n");

	nl_sk  =  netlink_kernel_create(&init_net,    NETLINK_USER, NULL);

	if (!nl_sk)  {
		printk(KERN_ALERT "Error creating socket.\n");
		return -10;
	}

	printk(KERN_INFO "NetLink Initialized!\n");

	mutex_init(&mutex_len);

	consumer_1  =  kthread_create(consumer_thread,    NULL, "consumer1");
	consumer_2  =  kthread_create(consumer_thread,    NULL, "consumer2");

	wake_up_process(consumer_1);
	wake_up_process(consumer_2);

	if  (sysptr  == NULL)
		sysptr  =  submitjob;
	return 0;
}

static void  __exit exit_sys_submitjob(void)
 {
	if  (sysptr !=  NULL)
		sysptr  =  NULL;

	exit_queue(q_actv);
	exit_queue(q_wait);

	module_exiting++;
	q_actv_len++;
	wake_up_all(&cons_wq);

wait:
	if (is_working) {
		msleep(200);
		printk(KERN_INFO "Consumer Busy\n");
		goto wait;
	}

	netlink_kernel_release(nl_sk);
	printk(KERN_INFO "Removed sys_submitjob module\n");
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("File for submitting the system call to the kernel");
MODULE_AUTHOR("VINAYAK/SOMESH/MANSI/ALPIT");
MODULE_ALIAS("test");
