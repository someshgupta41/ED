umount ../mnt
rmmod amfs.ko 
insmod amfs.ko
mount -t amfs -o pattdb=/mypatterns.db /usr/src/hw2-sogupta/hw2-sogupta/fs/mnt ../mntpt 
