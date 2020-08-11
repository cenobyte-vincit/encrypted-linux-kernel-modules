bool
is_elf64(int fd) 
{
	Elf64_Ehdr elf64;

	if (pread64(fd, &elf64, EI_NIDENT, 0) != EI_NIDENT)
		return(false);

	return(true);
}

long unsigned int
elf64_size(int fd)
{
	Elf64_Ehdr elf64;

	if (pread64(fd, &elf64, sizeof(elf64), 0) < 0) {
#ifdef DEBUG
		perror("pread");
#endif
		exit(1);
	}

	// If a file has no section header table, e_shnum holds the value zero
	if (elf64.e_shnum == 0) {
#ifdef DEBUG
		fprintf(stderr, "%s(): ELF has no section header table\n",
		    __FUNCTION__);
#endif
		return(0);
	}

#ifdef DEBUG
	fprintf(stderr, "%s(): elf64.e_shoff: %lu / 0x%jx\n", __FUNCTION__,
	    elf64.e_shoff, elf64.e_shoff);
	fprintf(stderr, "%s(): elf64.e_shentsize: %d\n", __FUNCTION__,
	    elf64.e_shentsize);
	fprintf(stderr, "%s(): elf64.e_shnum: %d\n", __FUNCTION__, elf64.e_shnum);
#endif

	return(elf64.e_shoff + elf64.e_shentsize * elf64.e_shnum);
}

long unsigned int
binsize(char *path)
{
	struct stat bin;

	if (stat(path, &bin) != 0) {
#ifdef DEBUG
		perror("stat");
#endif
		exit(1);
	}

	return(bin.st_size);
}
