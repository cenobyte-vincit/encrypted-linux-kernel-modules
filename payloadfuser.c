/*
 * ELKM payloadfuser.c - Encrypts a LKM and fuses it to the ELKM loader
 *
 *                by vincitamorpatriae@gmail.com
 */

#define _GNU_SOURCE
#define _XOPEN_SOURCE 500	/* pread64 */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>	/* RAND_bytes */

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto.h"
#include "elf64.h"

extern char *__progname;

int
main(int argc, char **argv)
{
	int loaderfd = 0;
	int lkmfd = 0;

	long unsigned int loadersize = 0;

	char *password;
	char *loaderpath;
	char *lkmpath;

	if (argc < 4) {
		fprintf(stderr, "usage: %s <kernel module> <loader> <password>\n",
		    __progname);
		exit(1);
	}

	lkmpath = argv[1];
	loaderpath = argv[2];
	password = argv[3];

	loaderfd = open(loaderpath, O_RDWR | O_APPEND);
	if (loaderfd < 0) {
		perror("open");
		exit(1);
	}

	if (!is_elf64(loaderfd)) {
		fprintf(stderr, "%s: '%s' is not a 64-bit ELF\n", __progname,
		    loaderpath);
		exit(1);
	}

	loadersize = elf64_size(loaderfd);	

	if (binsize(loaderpath) - loadersize != 0) {
		fprintf(stderr, "%s: payload appears to have been fused already\n",
		    __progname);
		exit(1);
	}

	lkmfd = open(lkmpath, O_RDONLY);
	if (lkmfd < 0) {
		perror("open");
		exit(1);
	}

	if (!is_elf64(lkmfd)) {
		fprintf(stderr, "%s: '%s' is not a LKM\n", __progname, lkmpath);
		exit(1);
	}

	fprintf(stderr, "%s(): encrypting '%s' with password '%s', and fusing with '%s'\n",
	    __FUNCTION__, lkmpath, password, loaderpath);

	if (!aes_crypt_fd(ENCRYPT, password, loaderfd, lkmfd)) {
		fprintf(stderr, "%s(): aes_crypt_fd() failed\n", __FUNCTION__);
		return(1);
	}

	close(loaderfd);
	close(lkmfd);

	return(0);
}
