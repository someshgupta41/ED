#define UDBG printk (KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#define MAX_Q_LEN 6

int job_id = 0;
int module_exiting = 0;
int is_working = 0;

struct queue_elem {
	jobs *job;
	struct queue_elem *next;
};

struct queue {
	struct queue_elem *head;
	struct queue_elem *tail;
	struct mutex mutex_queue;
};

struct queue *q_actv;
struct queue *q_wait;

struct sock *nl_sk = NULL;

int q_actv_len = 0;
int q_wait_len = 0;

wait_queue_head_t prod_wq, cons_wq;

struct mutex mutex_len;

struct task_struct *consumer_1;
struct task_struct *consumer_2;

int performActionByJob(jobs *job);

struct queue *init_queue(void)
{
	struct queue *q = kmalloc(sizeof(struct queue *), GFP_KERNEL);

	if (q == NULL) {
		return ERR_PTR(-ENOMEM);
	}
	else {
		q->head = NULL;
		q->tail = NULL;
	}

	mutex_init(&q->mutex_queue);
	return q;
}

struct queue *insertJob(struct queue *q, jobs *job)
{
	int err = 0;
	struct queue_elem *elem;

	if (q == NULL) {
		err = -EINVAL;
		goto out;
	}

	elem = kmalloc(sizeof(struct queue_elem *), GFP_KERNEL);

	if (elem == NULL) {
		err = -ENOMEM;
		goto out;
	}

	elem->job = job;
	elem->next = NULL;

	mutex_lock(&q->mutex_queue);
	if (q->head == NULL && q->tail == NULL) {
		q->head = elem;
		q->tail = elem;
	}
	else {
		q->tail->next = elem;
		q->tail = elem;
	}

	mutex_unlock(&q->mutex_queue);

out:

	if (err != 0)
		return ERR_PTR (err);
	else
		return q;
}

int removeJobByID(struct queue *q, int jid)
{
	int err = 0, isExist = 0;
	struct queue_elem *curr_elem = NULL, *prev_elem = NULL;

	if (q == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (q->head == NULL && q->tail == NULL) {
		err = -EINVAL;
		goto out;
	}

	mutex_lock(&q->mutex_queue);

	curr_elem = q->head;
	prev_elem = NULL;

	while (curr_elem) {
		if (curr_elem->job->job_id == jid) {
			if (curr_elem == q->head)
				q->head = curr_elem->next;
			else {
				prev_elem->next = curr_elem->next;

				if (prev_elem->next == NULL)
					q->tail = prev_elem;
			}

			isExist = 1;
			goto elem_found;
		}

		prev_elem = curr_elem;
		curr_elem = curr_elem->next;
	}

elem_found:
	if (q->head == NULL)
		q->tail = NULL;
	mutex_unlock (&q->mutex_queue);

	if (isExist == 1) {
		if (curr_elem->job->infile != NULL)
			kfree(curr_elem->job->infile);
		if (curr_elem->job->outfile != NULL)
			kfree(curr_elem->job->outfile);
		if (curr_elem->job->cipher != NULL)
			kfree(curr_elem->job->cipher);

		kfree(curr_elem->job);
		kfree(curr_elem);
	}
	else
		err = -ENOENT;

out:
	return err;
}

int changePriorityByID(struct queue *q, int jid, int priority)
{
	int err = 0, isExist = 0;
	struct queue_elem *curr_elem = NULL, *prev_elem = NULL;

	if (q == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (q->head == NULL && q->tail == NULL) {
		err = -EINVAL;
		goto out;
	}

	mutex_lock(&q->mutex_queue);

	curr_elem = q->head;
	prev_elem = NULL;

	while (curr_elem) {
		if (curr_elem->job->job_id == jid) {
			isExist = 1;
			goto elem_found;
		}

		prev_elem = curr_elem;
		curr_elem = curr_elem->next;
	}

elem_found:
	if (q->head == NULL)
		q->tail = NULL;
	mutex_unlock(&q->mutex_queue);

	if (isExist == 1)
		curr_elem->job->priority = priority;
	else
		err = -ENOENT;

out:
	return err;
}

struct job *getHighPriorityJob(struct queue *q)
{
	int err = 0, i;
	jobs *job;
	struct queue_elem *curr_elem = NULL, *prev_elem = NULL;

	if (q == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (q->head == NULL && q->tail == NULL) {
		err = -EINVAL;
		goto out;
	}

	mutex_lock(&q->mutex_queue);

	for (i = 1; i < 4; i++) {
		curr_elem = q->head;
		prev_elem = NULL;

		while (curr_elem) {
			if (curr_elem->job->priority == i) {
				if (curr_elem == q->head)
					q->head = curr_elem->next;
				else {
					prev_elem->next = curr_elem->next;

					if (prev_elem->next == NULL)
						q->tail = prev_elem;
				}

				goto elem_found;
			}

			prev_elem = curr_elem;
			curr_elem = curr_elem->next;
		}
	}

elem_found:
	if (q->head == NULL)
		q->tail = NULL;

	mutex_unlock(&q->mutex_queue);
	job = curr_elem->job;
	kfree(curr_elem);

out:
	if (err < 0)
		return ERR_PTR(err);

	return job;
}

struct job *removeJob(struct queue *q)
{
	int err = 0;
	jobs *job;
	struct queue_elem *elem_1 = NULL, *elem_2 = NULL;

	if (q == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (q->head == NULL && q->tail == NULL) {
		err = -EINVAL;
		goto out;
	}

	mutex_lock(&q->mutex_queue);
	elem_1 = q->head;
	elem_2 = q->head->next;
	q->head = elem_2;
	job = elem_1->job;

	if (q->head == NULL)
		q->tail = NULL;

	mutex_unlock(&q->mutex_queue);

	kfree(elem_1);

out:
	if (err != 0)
		return ERR_PTR (err);

	return job;
}

void exit_queue(struct queue *q)
{
	jobs *job;
	struct queue_elem *elem, *n_elem;

	elem = q->head;

	while (elem) {
		n_elem = elem->next;
		job = removeJob(q);
		if (job->infile != NULL)
			kfree(job->infile);
		if (job->outfile != NULL)
			kfree(job->outfile);
		if (job->cipher != NULL)
			kfree(job->cipher);

		kfree(job);
		elem = n_elem;
	}

	kfree(q);
}
