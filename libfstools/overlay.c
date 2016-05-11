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

#include "libfstools.h"
#include "volume.h"

#define SWITCH_JFFS2 "/tmp/.switch_jffs2"

static bool keep_sysupgrade;

static int
handle_rmdir(const char *dir)
{
	struct dirent *dt;
	struct stat st;
	DIR *d;
	int fd;

	d = opendir(dir);
	if (!d)
		return -1;

	fd = dirfd(d);

	while ((dt = readdir(d)) != NULL) {
		if (fstatat(fd, dt->d_name, &st, AT_SYMLINK_NOFOLLOW) || S_ISDIR(st.st_mode))
			continue;

		if (keep_sysupgrade && !strcmp(dt->d_name, "sysupgrade.tgz"))
			continue;

		unlinkat(fd, dt->d_name, 0);
	}

	closedir(d);
	rmdir(dir);

	return 0;
}

void
foreachdir(const char *dir, int (*cb)(const char*))
{
	struct stat s = { 0 };
	char globdir[256];
	glob_t gl;
	int j;

	if (dir[strlen(dir) - 1] == '/')
		snprintf(globdir, 256, "%s*", dir);
	else
		snprintf(globdir, 256, "%s/*", dir); /**/

	if (!glob(globdir, GLOB_NOESCAPE | GLOB_MARK | GLOB_ONLYDIR, NULL, &gl))
		for (j = 0; j < gl.gl_pathc; j++) {
			char *dir = gl.gl_pathv[j];
			int len = strlen(gl.gl_pathv[j]);

			if (len > 1 && dir[len - 1] == '/')
				dir[len - 1] = '\0';

			if (!lstat(gl.gl_pathv[j], &s) && !S_ISLNK(s.st_mode))
				foreachdir(gl.gl_pathv[j], cb);
	}
	cb(dir);
}

void
overlay_delete(const char *dir, bool _keep_sysupgrade)
{
	keep_sysupgrade = _keep_sysupgrade;
	foreachdir(dir, handle_rmdir);
}

static int
overlay_mount(struct volume *v, char *fs)
{
	if (mkdir("/tmp/overlay", 0755)) {
		ULOG_ERR("failed to mkdir /tmp/overlay: %s\n", strerror(errno));
		return -1;
	}

	if (mount(v->blk, "/tmp/overlay", fs, MS_NOATIME, NULL)) {
		ULOG_ERR("failed to mount -t %s %s /tmp/overlay: %s\n", fs, v->blk, strerror(errno));
		return -1;
	}

	return volume_init(v);
}

static int
switch2jffs(struct volume *v)
{
	struct stat s;
	int ret;

	if (!stat(SWITCH_JFFS2, &s)) {
		ULOG_ERR("jffs2 switch already running\n");
		return -1;
	}

	creat("/tmp/.switch_jffs2", 0600);
	ret = mount(v->blk, "/rom/overlay", "jffs2", MS_NOATIME, NULL);
	unlink("/tmp/.switch_jffs2");
	if (ret) {
		ULOG_ERR("failed - mount -t jffs2 %s /rom/overlay: %s\n", v->blk, strerror(errno));
		return -1;
	}

	if (mount("none", "/", NULL, MS_NOATIME | MS_REMOUNT, 0)) {
		ULOG_ERR("failed - mount -o remount,ro none: %s\n", strerror(errno));
		return -1;
	}

	if (system("cp -a /tmp/root/* /rom/overlay")) {
		ULOG_ERR("failed - cp -a /tmp/root/* /rom/overlay: %s\n", strerror(errno));
		return -1;
	}

	if (pivot("/rom", "/mnt")) {
		ULOG_ERR("failed - pivot /rom /mnt: %s\n", strerror(errno));
		return -1;
	}

	if (mount_move("/mnt", "/tmp/root", "")) {
		ULOG_ERR("failed - mount -o move /mnt /tmp/root %s\n", strerror(errno));
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

int
jffs2_switch(struct volume *v)
{
	char *mp;
	int ret = -1;

	if (find_overlay_mount("overlayfs:/tmp/root"))
		return -1;

	if (find_filesystem("overlay")) {
		ULOG_ERR("overlayfs not supported by kernel\n");
		return ret;
	}

	mp = find_mount_point(v->blk, 0);
	if (mp) {
		ULOG_ERR("rootfs_data:%s is already mounted as %s\n", v->blk, mp);
		return -1;
	}

	switch (volume_identify(v)) {
	case FS_NONE:
		ULOG_ERR("no jffs2 marker found\n");
		/* fall through */

	case FS_DEADCODE:
		ret = switch2jffs(v);
		if (!ret) {
			ULOG_INFO("performing overlay whiteout\n");
			umount2("/tmp/root", MNT_DETACH);
			foreachdir("/overlay/", handle_whiteout);
		}
		break;

	case FS_JFFS2:
		ret = overlay_mount(v, "jffs2");
		if (ret)
			break;
		if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
			ULOG_ERR("switching to jffs2 failed\n");
			ret = -1;
		}
		break;

	case FS_UBIFS:
		ret = overlay_mount(v, "ubifs");
		if (ret)
			break;
		if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
			ULOG_ERR("switching to ubifs failed\n");
			ret = -1;
		}
		break;
	}

	if (ret)
		return ret;

	sync();
	fs_state_set("/overlay", FS_STATE_READY);
	return 0;
}

static int overlay_mount_fs(struct volume *v)
{
	char *fstype;

	if (mkdir("/tmp/overlay", 0755)) {
		ULOG_ERR("failed to mkdir /tmp/overlay: %s\n", strerror(errno));
		return -1;
	}

	fstype = "jffs2";

	switch (volume_identify(v)) {
	case FS_UBIFS:
		fstype = "ubifs";
		break;
	}

	volume_init(v);

	if (mount(v->blk, "/tmp/overlay", fstype, MS_NOATIME, NULL)) {
		ULOG_ERR("failed to mount -t %s %s /tmp/overlay: %s\n",
		         fstype, v->blk, strerror(errno));
		return -1;
	}

	return -1;
}

enum fs_state fs_state_get(const char *dir)
{
	char *path;
	char valstr[16];
	uint32_t val;
	ssize_t len;

	path = alloca(strlen(dir) + 1 + sizeof("/.fs_state"));
	sprintf(path, "%s/.fs_state", dir);
	len = readlink(path, valstr, sizeof(valstr) - 1);
	if (len < 0)
		return FS_STATE_UNKNOWN;

	valstr[len] = 0;
	val = atoi(valstr);

	if (val > __FS_STATE_LAST)
		return FS_STATE_UNKNOWN;

	return val;
}


int fs_state_set(const char *dir, enum fs_state state)
{
	char valstr[16];
	char *path;

	if (fs_state_get(dir) == state)
		return 0;

	path = alloca(strlen(dir) + 1 + sizeof("/.fs_state"));
	sprintf(path, "%s/.fs_state", dir);
	unlink(path);
	snprintf(valstr, sizeof(valstr), "%d", state);

	return symlink(valstr, path);
}


int mount_overlay(struct volume *v)
{
	char *mp;

	if (!v)
		return -1;

	mp = find_mount_point(v->blk, 0);
	if (mp) {
		ULOG_ERR("rootfs_data:%s is already mounted as %s\n", v->blk, mp);
		return -1;
	}

	overlay_mount_fs(v);

	extroot_prefix = "/tmp/overlay";
	if (!mount_extroot()) {
		ULOG_INFO("switched to extroot\n");
		return 0;
	}

	switch(fs_state_get("/tmp/overlay")) {
	case FS_STATE_UNKNOWN:
		fs_state_set("/tmp/overlay", FS_STATE_PENDING);
		if (fs_state_get("/tmp/overlay") != FS_STATE_PENDING) {
			ULOG_ERR("unable to set filesystem state\n");
			break;
		}
	case FS_STATE_PENDING:
		ULOG_INFO("overlay filesystem has not been fully initialized yet\n");
		overlay_delete("/tmp/overlay", true);
		break;
	case FS_STATE_READY:
		break;
	}

	ULOG_INFO("switching to jffs2 overlay\n");
	if (mount_move("/tmp", "", "/overlay") || fopivot("/overlay", "/rom")) {
		ULOG_ERR("switching to jffs2 failed - fallback to ramoverlay\n");
		return ramoverlay();
	}

	return -1;
}
