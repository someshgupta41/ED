	
#define MAGIC_NUMBER 'G'
#define LIST_IOCTL _IOR(MAGIC_NUMBER, 0, int)
#define ADD_IOCTL _IOW(MAGIC_NUMBER,1,int)
#define REMOVE_IOCTL _IOW(MAGIC_NUMBER, 2, int)