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
#include <sys/types.h>
#include <sys/mount.h>

#include <asm/byteorder.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <glob.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#include "../fs-state.h"
#include "../lib/mtd.h"

#define SWITCH_JFFS2 "/tmp/.switch_jffs2"

void
foreachdir(const char *dir, int (*cb)(const char*))
{
	char globdir[256];
	glob_t gl;
	int j;

	if (dir[strlen(dir) - 1] == '/')
		snprintf(globdir, 256, "%s*", dir);
	else
		snprintf(globdir, 256, "%s/*", dir);

	if (!glob(globdir, GLOB_NOESCAPE | GLOB_MARK | GLOB_ONLYDIR, NULL, &gl))
		for (j = 0; j < gl.gl_pathc; j++)
			foreachdir(gl.gl_pathv[j], cb);

	cb(dir);
}

static int
jffs2_mount(void)
{
	char rootfs_data[32];
	int fd;

	if (mkdir("/tmp/overlay", 0755)) {
		fprintf(stderr, "failed to mkdir /tmp/overlay: %s\n", strerror(errno));
		return -1;
	}

	if (find_mtd_block("rootfs_data", rootfs_data, sizeof(rootfs_data))) {
		fprintf(stderr, "rootfs_data does not exist\n");
		return -1;
	}

	if (mount(rootfs_data, "/tmp/overlay", "jffs2", MS_NOATIME, NULL)) {
		fprintf(stderr, "failed to mount -t jffs2 %s /tmp/overlay: %s\n", rootfs_data, strerror(errno));
		return -1;
	}

	find_mtd_char("rootfs_data", rootfs_data, sizeof(rootfs_data));

	fd = mtd_load(rootfs_data);
	if (fd > 0) {
		int ret = mtd_unlock(fd);
		close(fd);
		return ret;
	}

	return -1;
}

static int
switch2jffs(void)
{
	struct stat s;
	char mtd[32];
	int ret;

	if (!stat(SWITCH_JFFS2, &s)) {
		fprintf(stderr, "jffs2 switch already running\n");
		return -1;
	}

	if (!find_mtd_block("rootfs_patches", mtd, sizeof(mtd)))
		return 0;

	if (find_mtd_block("rootfs_data", mtd, sizeof(mtd))) {
		fprintf(stderr, "no rootfs_data was found\n");
		return -1;
	}

	creat("/tmp/.switch_jffs2", 0600);
	ret = mount(mtd, "/rom/overlay", "jffs2", MS_NOATIME, NULL);
	unlink("/tmp/.switch_jffs2");
	if (ret) {
		fprintf(stderr, "failed - mount -t jffs2 %s /rom/overlay: %s\n", mtd, strerror(errno));
		return -1;
	}

	if (mount("none", "/", NULL, MS_NOATIME | MS_REMOUNT, 0)) {
		fprintf(stderr, "failed - mount -o remount,ro none: %s\n", strerror(errno));
		return -1;
	}

	system("cp -a /tmp/root/* /rom/overlay");

	if (pivot("/rom", "/mnt")) {
		fprintf(stderr, "failed - pivot /rom /mnt: %s\n", strerror(errno));
		return -1;
	}

	if (mount_move("/mnt", "/tmp/root", "")) {
		fprintf(stderr, "failed - mount -o move /mnt /tmp/root %s\n", strerror(errno));
		return -1;
	}

	return fopivot("/overlay", "/rom");
}

int
handle_whiteout(const char *dir)
{
	struct stat s;
	char link[256];
	ssize_t sz;
	struct dirent **namelist;
	int n;

	n = scandir(dir, &namelist, NULL, NULL);

	if (n < 1)
		return -1;

	while (n--) {
		char file[256];

		snprintf(file, sizeof(file), "%s%s", dir, namelist[n]->d_name);
		if (!lstat(file, &s) && S_ISLNK(s.st_mode)) {
			sz = readlink(file, link, sizeof(link) - 1);
			if (sz > 0) {
				char *orig;

				link[sz] = '\0';
				orig = strstr(&file[1], "/");
				if (orig && !strcmp(link, "(overlay-whiteout)"))
					unlink(orig);
			}
		}
		free(namelist[n]);
	}
	free(namelist);

	return 0;
}

static int
ask_user(int argc, char **argv)
{
	if ((argc < 2) || strcmp(argv[1], "-y")) {
		fprintf(stderr, "This will erase all settings and remove any installed packages. Are you sure? [N/y]\n");
		if (getchar() != 'y')
			return -1;
	}
	return 0;

}

static int
handle_rmdir(const char *dir)
{
	struct stat s;
	struct dirent **namelist;
	int n;

	n = scandir(dir, &namelist, NULL, NULL);

	if (n < 1)
		return -1;

	while (n--) {
		char file[256];

		snprintf(file, sizeof(file), "%s%s", dir, namelist[n]->d_name);
		if (!lstat(file, &s) && !S_ISDIR(s.st_mode))
			unlink(file);
		free(namelist[n]);
	}
	free(namelist);

	rmdir(dir);

	return 0;
}

static int
jffs2_reset(int argc, char **argv)
{
	char mtd[32];
	char *mp;

	if (ask_user(argc, argv))
		return -1;

	if (find_filesystem("overlay")) {
		fprintf(stderr, "overlayfs not found\n");
		return -1;
	}

	if (find_mtd_block("rootfs_data", mtd, sizeof(mtd))) {
		fprintf(stderr, "no rootfs_data was found\n");
		return -1;
	}

	mp = find_mount_point(mtd, "jffs2");
	if (mp) {
		fprintf(stderr, "%s is mounted as %s, only erasing files\n", mtd, mp);
		foreachdir(mp, handle_rmdir);
		mount(mp, "/", NULL, MS_REMOUNT, 0);
	} else {
		int fd;
		fprintf(stderr, "%s is not mounted, erasing it\n", mtd);
		find_mtd_char("rootfs_data", mtd, sizeof(mtd));
		fd = mtd_load(mtd);
		if (fd > 0) {
			mtd_erase(fd, 0, mtdsize / erasesize);
			close(fd);
		}
	}

	return 0;
}

static int
jffs2_mark(int argc, char **argv)
{
	FILE *fp;
	__u32 deadc0de = __cpu_to_be32(0xdeadc0de);
	char mtd[32];
	size_t sz;

	if (ask_user(argc, argv))
		return -1;

	if (find_mtd_block("rootfs_data", mtd, sizeof(mtd))) {
		fprintf(stderr, "no rootfs_data was found\n");
		return -1;
	}

	fp = fopen(mtd, "w");
	fprintf(stderr, "%s - marking with deadc0de\n", mtd);
	if (!fp) {
		fprintf(stderr, "opening %s failed\n", mtd);
		return -1;
	}

	sz = fwrite(&deadc0de, sizeof(deadc0de), 1, fp);
	fclose(fp);

	if (sz != 1) {
		fprintf(stderr, "writing %s failed: %s\n", mtd, strerror(errno));
		return -1;
	}

	return 0;
}

int
jffs2_switch(int argc, char **argv)
{
	char mtd[32];
	char *mp;
	int ret = -1;

	if (find_overlay_mount("overlayfs:/tmp/root"))
		return -1;

	if (find_filesystem("overlay")) {
		fprintf(stderr, "overlayfs not found\n");
		return ret;
	}

	find_mtd_block("rootfs_data", mtd, sizeof(mtd));
	mp = find_mount_point(mtd, NULL);
	if (mp) {
		fprintf(stderr, "rootfs_data:%s is already mounted as %s\n", mtd, mp);
		return -1;
	}

	if (find_mtd_char("rootfs_data", mtd, sizeof(mtd))) {
		fprintf(stderr, "no rootfs_data was found\n");
		return ret;
	}

	switch (mtd_identify(mtd)) {
	case FS_NONE:
		fprintf(stderr, "no jffs2 marker found\n");
		/* fall through */

	case FS_DEADCODE:
		ret = switch2jffs();
		if (!ret) {
			fprintf(stderr, "doing fo cleanup\n");
			umount2("/tmp/root", MNT_DETACH);
			foreachdir("/overlay/", handle_whiteout);
		}
		break;

	case FS_JFFS2:
		ret = jffs2_mount();
		if (ret)
			break;
		if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
			fprintf(stderr, "switching to jffs2 failed\n");
			ret = -1;
		}
		break;
	}

	return ret;
}

static int mtd_mount_jffs2(void)
{
	char rootfs_data[32];
	int fd;

	if (mkdir("/tmp/overlay", 0755)) {
		fprintf(stderr, "failed to mkdir /tmp/overlay: %s\n", strerror(errno));
		return -1;
	}

	if (find_mtd_block("rootfs_data", rootfs_data, sizeof(rootfs_data))) {
		fprintf(stderr, "rootfs_data does not exist\n");
		return -1;
	}

	if (mount(rootfs_data, "/tmp/overlay", "jffs2", MS_NOATIME, NULL)) {
		fprintf(stderr, "failed to mount -t jffs2 %s /tmp/overlay: %s\n", rootfs_data, strerror(errno));
		return -1;
	}

	find_mtd_char("rootfs_data", rootfs_data, sizeof(rootfs_data));

	fd = mtd_load(rootfs_data);
	if (fd) {
		int ret = mtd_unlock(fd);
		close(fd);
		return ret;
	}

	return -1;
}

static int overlay_mount(void)
{
	char mtd[32];
	char *mp;

	find_mtd_block("rootfs_data", mtd, sizeof(mtd));
	mp = find_mount_point(mtd, NULL);
	if (mp) {
		fprintf(stderr, "rootfs_data:%s is already mounted as %s\n", mtd, mp);
		return -1;
	}

	mtd_mount_jffs2();

	extroot_prefix = "/tmp/overlay";
	if (!backend_mount("extroot")) {
		fprintf(stderr, "fs-state: switched to extroot\n");
		return 0;
	}

	fprintf(stderr, "switching to jffs2\n");
	if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
		fprintf(stderr, "switching to jffs2 failed - fallback to ramoverlay\n");
		return ramoverlay();
	}

	return -1;
}

static struct backend_handler jffs2_handlers[] = {
{
	.name = "jffs2reset",
	.cli = jffs2_reset,
}, {
	.name = "jffs2mark",
	.cli = jffs2_mark,
}};

static struct backend overlay_backend = {
	.name = "overlay",
	.num_handlers = ARRAY_SIZE(jffs2_handlers),
	.handlers = jffs2_handlers,
	.mount = overlay_mount,
};
BACKEND(overlay_backend);
