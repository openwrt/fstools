/*
 * Copyright (C) 2014 John Crispin <blogic@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <asm/byteorder.h>
#include <mtd/mtd-user.h>

#include <errno.h>
#include <glob.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <string.h>

#include "../fs-state.h"
#include "mtd.h"

#define PATH_MAX	256

int mtdsize = 0;
int erasesize = 0;

int
mtd_open(const char *mtd, int block)
{
	FILE *fp;
	char dev[PATH_MAX];
	int i, ret, flags = O_RDWR | O_SYNC;

	if ((fp = fopen("/proc/mtd", "r"))) {
		while (fgets(dev, sizeof(dev), fp)) {
			if (sscanf(dev, "mtd%d:", &i) && strstr(dev, mtd)) {
				snprintf(dev, sizeof(dev), "/dev/mtd%s/%d", (block ? "block" : ""), i);
				ret = open(dev, flags);
				if (ret < 0) {
					snprintf(dev, sizeof(dev), "/dev/mtd%s%d", (block ? "block" : ""), i);
					ret = open(dev, flags);
				}
				fclose(fp);
				return ret;
			}
		}
		fclose(fp);
	}

	return open(mtd, flags);
}

int
mtd_load(const char *mtd)
{
	struct mtd_info_user mtdInfo;
	struct erase_info_user mtdLockInfo;
	int fd;

	fd = mtd_open(mtd, 0);
	if (fd < 0) {
		fprintf(stderr, "Could not open mtd device: %s\n", mtd);
		return -1;
	}

	if (ioctl(fd, MEMGETINFO, &mtdInfo)) {
		fprintf(stderr, "Could not get MTD device info from %s\n", mtd);
		close(fd);
		return -1;
	}

	mtdsize = mtdInfo.size;
	erasesize = mtdInfo.erasesize;

	mtdLockInfo.start = 0;
	mtdLockInfo.length = mtdsize;
	ioctl(fd, MEMUNLOCK, &mtdLockInfo);

	return fd;
}

void
mtd_erase(int fd, int first_block, int num_blocks)
{
	struct erase_info_user eiu;

	eiu.length = erasesize;
	for (eiu.start = first_block * erasesize;
			eiu.start < mtdsize && eiu.start < (first_block + num_blocks) * erasesize;
			eiu.start += erasesize) {
		fprintf(stderr, "erasing %x %x\n", eiu.start, erasesize);
		ioctl(fd, MEMUNLOCK, &eiu);
		if (ioctl(fd, MEMERASE, &eiu))
			fprintf(stderr, "Failed to erase block at 0x%x\n", eiu.start);
	}
}

int
mtd_unlock(int fd)
{
	struct mtd_info_user mtdinfo;
	int ret = ioctl(fd, MEMGETINFO, &mtdinfo);

	if (ret) {
		fprintf(stderr, "ioctl(%d, MEMGETINFO) failed: %s\n", fd, strerror(errno));
	} else {
		struct erase_info_user mtdlock;

		mtdlock.start = 0;
		mtdlock.length = mtdinfo.size;
		ioctl(fd, MEMUNLOCK, &mtdlock);
	}

	return ret;
}

int
mtd_read_buffer(int fd, void *buf, int offset, int length)
{
	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		fprintf(stderr, "lseek/read failed\n");
		return -1;
	}

	if (read(fd, buf, length) == -1) {
		fprintf(stderr, "read failed\n");
		return -1;
	}

	return 0;
}

int
mtd_write_buffer(int fd, void *buf, int offset, int length)
{
	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		fprintf(stderr, "lseek/write failed at offset %d\n", offset);
		perror("lseek");
		return -1;
	}

	if (write(fd, buf, length) == -1) {
		fprintf(stderr, "write failed\n");
		return -1;
	}

	return 0;
}

int
mtd_identify(char *mtd)
{
	int fd = mtd_load(mtd);
	__u32 deadc0de;
	__u16 jffs2;
	size_t sz;

	if (!fd) {
		fprintf(stderr, "reading %s failed\n", mtd);
		return -1;
	}

	sz = read(fd, &deadc0de, sizeof(deadc0de));
	close(fd);

	if (sz != sizeof(deadc0de)) {
		fprintf(stderr, "reading %s failed: %s\n", mtd, strerror(errno));
		return -1;
	}

	if (deadc0de == 0x4f575254)
		return FS_SNAPSHOT;

	deadc0de = __be32_to_cpu(deadc0de);
	jffs2 = __be16_to_cpu(deadc0de >> 16);

	if (jffs2 == 0x1985) {
		fprintf(stderr, "jffs2 is ready\n");
		return FS_JFFS2;
	}

	if (deadc0de == 0xdeadc0de) {
		fprintf(stderr, "jffs2 is not ready - marker found\n");
		return FS_DEADCODE;
	}

	fprintf(stderr, "No jffs2 marker was found\n");

	return FS_NONE;
}
