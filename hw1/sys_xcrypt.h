#define __NR_xcrypt 359

typedef struct kl_mod_args{

	char *infile;
	char *outfile;
	char *keybuf;
	int keylen; 	
	int encdecflag;
}args;
