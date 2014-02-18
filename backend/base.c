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

#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>

#include "../lib/mtd.h"
#include "../fs-state.h"

int
backend_mount(char *name)
{
	struct backend *b = find_backend(name);

	if (!b || !b->mount)
		return -1;

	return b->mount();
}

static int
backend_info(char *name)
{
	struct backend *b = find_backend(name);

	if (!b || !b->info)
		return -1;

	return b->info();
}

static int
start(int argc, char **argv)
{
	char mtd[32];

	if (!getenv("PREINIT"))
		return -1;

	if (find_mtd_char("rootfs_data", mtd, sizeof(mtd))) {
		if (!find_mtd_char("rootfs", mtd, sizeof(mtd))) {
			int fd = mtd_load(mtd);
			if (fd > 0)
				mtd_unlock(fd);
		}
		fprintf(stderr, "mounting /dev/root\n");
		mount("/dev/root", "/", NULL, MS_NOATIME | MS_REMOUNT, 0);
		return 0;
	}

	extroot_prefix = "";
	if (!backend_mount("extroot")) {
		fprintf(stderr, "fs-state: switched to extroot\n");
		return 0;
	}

	switch (mtd_identify(mtd)) {
	case FS_NONE:
	case FS_DEADCODE:
		return ramoverlay();

	case FS_JFFS2:
		backend_mount("overlay");
		break;

	case FS_SNAPSHOT:
		backend_mount("snapshot");
		break;
	}

	return 0;
}

static int
stop(int argc, char **argv)
{
	if (!getenv("SHUTDOWN"))
		return -1;

	return 0;
}

static int
done(int argc, char **argv)
{
	char mtd[32];

	if (find_mtd_char("rootfs_data", mtd, sizeof(mtd)))
		return -1;

	switch (mtd_identify(mtd)) {
	case FS_NONE:
	case FS_DEADCODE:
		return jffs2_switch(argc, argv);
	}

	return 0;
}

static int
info(int argc, char **argv)
{
	char mtd[32];

	if (find_mtd_char("rootfs_data", mtd, sizeof(mtd)))
		return -1;

	switch (mtd_identify(mtd)) {
	case FS_SNAPSHOT:
		backend_info("snapshot");
		return 0;
	}

	return 0;
}

static struct backend start_backend = {
	.name = "start",
	.cli = start,
};
BACKEND(start_backend);

static struct backend stop_backend = {
	.name = "stop",
	.cli = stop,
};
BACKEND(stop_backend);

static struct backend done_backend = {
	.name = "done",
	.cli = done,
};
BACKEND(done_backend);

static struct backend info_backend = {
	.name = "info",
	.cli = info,
};
BACKEND(info_backend);
