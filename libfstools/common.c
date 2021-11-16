// SPDX-License-Identifier: GPL-2.0-or-later

#include "common.h"
#define BUFLEN 128

int
read_uint_from_file(char *dirname, char *filename, unsigned int *i)
{
	FILE *f;
	char fname[BUFLEN];
	int ret = -1;

	snprintf(fname, sizeof(fname), "%s/%s", dirname, filename);

	f = fopen(fname, "r");
	if (!f)
		return ret;

	if (fscanf(f, "%u", i) == 1)
		ret = 0;

	fclose(f);
	return ret;
}

char
*read_string_from_file(const char *dirname, const char *filename, char *buf, size_t bufsz)
{
	FILE *f;
	char fname[BUFLEN];
	int i;

	snprintf(fname, sizeof(fname), "%s/%s", dirname, filename);

	f = fopen(fname, "r");
	if (!f)
		return NULL;

	if (fgets(buf, bufsz, f) == NULL) {
		fclose(f);
		return NULL;
	}

	fclose(f);

	/* make sure the string is \0 terminated */
	buf[bufsz - 1] = '\0';

	/* remove trailing whitespace */
	i = strlen(buf) - 1;
	while (i > 0 && buf[i] <= ' ')
		buf[i--] = '\0';

	return buf;
}

int block_file_identify(FILE *f, uint64_t offset)
{
	uint32_t magic = 0;
	size_t n;

	if (fseeko(f, offset, SEEK_SET) < 0)
		return -1;

	n = fread(&magic, sizeof(magic), 1, f);
	if (magic == cpu_to_le32(0x88b1f)) {
		return FS_TARGZ;
	}

	if (fseeko(f, offset + 0x400, SEEK_SET) < 0)
		return -1;

	n = fread(&magic, sizeof(magic), 1, f);
	if (n != 1)
		return -1;

	if (magic == cpu_to_le32(0xF2F52010))
		return FS_F2FS;

	magic = 0;
	if (fseeko(f, offset + 0x438, SEEK_SET) < 0)
		return -1;

	n = fread(&magic, sizeof(magic), 1, f);
	if (n != 1)
		return -1;

	if ((le32_to_cpu(magic) & 0xffff) == 0xef53)
		return FS_EXT4;

	return FS_NONE;
}

static bool use_f2fs(struct volume *v, uint64_t offset, const char *bdev)
{
	uint64_t size = 0;
	bool ret = false;
	int fd;

	fd = open(bdev, O_RDONLY);
	if (fd < 0)
		return false;

	if (ioctl(fd, BLKGETSIZE64, &size) == 0)
		ret = size - offset > F2FS_MINSIZE;

	close(fd);

	return ret;
}

int block_volume_format(struct volume *v, uint64_t offset, const char *bdev)
{
	int ret = 0;
	char str[128];

	switch (volume_identify(v)) {
	case FS_TARGZ:
		snprintf(str, sizeof(str), "gzip -cd %s > /tmp/sysupgrade.tar", v->blk);
		system(str);
		/* fall-through */
	case FS_NONE:
		ULOG_INFO("overlay filesystem in %s has not been formatted yet\n", v->blk);
		if (use_f2fs(v, offset, bdev))
			snprintf(str, sizeof(str), "mkfs.f2fs -q -l rootfs_data %s", v->blk);
		else
			snprintf(str, sizeof(str), "mkfs.ext4 -q -L rootfs_data %s", v->blk);

		ret = system(str);
		break;
	default:
		break;
	}

	return ret;
}
