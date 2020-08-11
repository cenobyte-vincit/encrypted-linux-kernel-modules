#define CIPHER "aes-256-cbc"
#define MDIGEST "sha512"
#define ITERATION_COUNT 10000
#define SALT_LENGTH 8
#define ENCRYPT 1
#define DECRYPT 0
#define MEGABYTE 1048576

bool
aes_crypt_fd(int operation, const char *password, int outfd, int infd)
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	const EVP_CIPHER *cipher = EVP_get_cipherbyname(CIPHER);
 	const EVP_MD *digest = NULL;

	int i = 0;
	int len = 0;
	int read_size = 0;
	int final_len = 0;
	
	unsigned char inbuf[MEGABYTE];
	unsigned char outbuf[MEGABYTE + EVP_CIPHER_block_size(cipher) - 1];
	unsigned char salt[SALT_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char key[EVP_MAX_KEY_LENGTH];

	if (cipher == NULL) {
#ifdef DEBUG
		fprintf(stderr, "%s(): no '%s' cipher\n", __FUNCTION__, CIPHER);
#endif
		return(false);
	}

	if (operation == ENCRYPT) {
		memset(salt, 0, SALT_LENGTH);
		if (RAND_bytes(salt, SALT_LENGTH) != 1) {
#ifdef DEBUG
			perror("RAND_bytes");
#endif
			return(false);
		}

		for (i = 0; i < SALT_LENGTH; i++)
			write(outfd, &salt[i], 1);
	} else {
		for (i = 0; i < SALT_LENGTH; i++)
			read(infd, &salt[i], 1);
	}

	digest = EVP_get_digestbyname(MDIGEST);
	if (!digest) {
#ifdef DEBUG
		fprintf(stderr, "%s(): unknown message digest %s\n", __FUNCTION__,
		    MDIGEST);
#endif
		return(false);
	}

	if (EVP_BytesToKey(cipher, digest, salt, (unsigned char *)password,
	    strlen(password), ITERATION_COUNT, key, iv) == 0) {
#ifdef DEBUG
		perror("EVP_BytesToKey");
#endif
		return(false);
	}

#ifdef DEBUG
	fprintf(stderr, "%s(): key[%d]: ", __FUNCTION__, cipher->key_len);
	for (i = 0; i < cipher->key_len; i++)
		fprintf(stderr, "0x%02x ", key[i]);
	
	fprintf(stderr, "\n%s(): salt[%d]: ", __FUNCTION__, SALT_LENGTH);
	for (i = 0; i < SALT_LENGTH; i++)
		fprintf(stderr, "0x%02x ", salt[i]);

	fprintf(stderr, "\n%s(): IV[%d]: ", __FUNCTION__, cipher->iv_len);
	for (i = 0; i < cipher->iv_len; i++)
		fprintf(stderr, "0x%02x ", iv[i]);

	fprintf(stderr, "\n");
#endif

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	if (EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, operation) == 0) {
#ifdef DEBUG
		perror("EVP_CipherInit_ex");
#endif
		EVP_CIPHER_CTX_cleanup(&ctx);
		return(false);
	}
	
	while ((read_size = read(infd, inbuf, MEGABYTE)) > 0) {
#ifdef DEBUG
		fprintf(stderr, "%s(): read %d bytes\n", __FUNCTION__, read_size);
#endif
		if (EVP_CipherUpdate(&ctx, outbuf, &len, inbuf, read_size) != 1) {
#ifdef DEBUG
			perror("EVP_CipherUpdate");
#endif
			EVP_CIPHER_CTX_cleanup(&ctx);
			return(false);
		}

#ifdef DEBUG
		fprintf(stderr, "%s(): got back %d bytes from infd\n", __FUNCTION__,
		    len);
		fprintf(stderr, "%s(): writing %d bytes\n", __FUNCTION__, len);
#endif
		if (write(outfd, outbuf, len) != len) {
#ifdef DEBUG
			perror("write");
#endif
			EVP_CIPHER_CTX_cleanup(&ctx);
			return(false);
		}
#ifdef DEBUG
		fprintf(stderr, "%s(): wrote %d bytes to outfd\n", __FUNCTION__, len);
#endif		
	}
	
	if (read_size == -1) {
#ifdef DEBUG
		fprintf(stderr, "%s(): reading from infd failed\n", __FUNCTION__);
#endif
		EVP_CIPHER_CTX_cleanup(&ctx);
		return(false);
	}
	
	if (EVP_CipherFinal_ex(&ctx, outbuf, &final_len) != 1) {
#ifdef DEBUG
		fprintf(stderr, "%s(): couldn't decrypt because of a wrong password\n",
		    __FUNCTION__);
#endif
		EVP_CIPHER_CTX_cleanup(&ctx);
		return(false);
	}
	
	if (final_len) {
#ifdef DEBUG
		fprintf(stderr, "%s(): writing final %d bytes\n", __FUNCTION__,
		    final_len);
#endif
		if (write(outfd, outbuf, final_len) != final_len) {
#ifdef DEBUG
			perror("write");
#endif
			EVP_CIPHER_CTX_cleanup(&ctx);
			return(false);
		}
#ifdef DEBUG
		fprintf(stderr, "%s(): wrote last %d bytes\n", __FUNCTION__, final_len);
#endif
	}

	memset(inbuf, 0, sizeof(inbuf));
	memset(outbuf, 0, sizeof(outbuf));
	memset(salt, 0, sizeof(salt));
	memset(key, 0, sizeof(key));
	memset(iv, 0, sizeof(iv));

	return(true);
}
