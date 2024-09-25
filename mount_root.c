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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <libubox/ulog.h>

#include "libfstools/libfstools.h"
#include "libfstools/volume.h"
#include "libfstools/common.h"

#define BUFLEN 64

/*
 * Called in the early (PREINIT) stage, when we immediately need some writable
 * filesystem.
 */
static int
start(int argc, char *argv[3])
{
	char dataparam[BUFLEN];
	char *dataname = "rootfs_data";
	struct volume *root;
	struct volume *data;
	struct stat s;

	if (get_var_from_file("/proc/cmdline", "fstools_overlay_name", dataparam, sizeof(dataparam)))
		dataname = dataparam;

	data = volume_find(dataname);

	if (!getenv("PREINIT") && stat("/tmp/.preinit", &s))
		return -1;

	if (!data) {
		root = volume_find("rootfs");
		volume_init(root);
		if (argc < 3)
			ULOG_NOTE("mounting /dev/root\n");
		else
			ULOG_NOTE("mounting /dev/root with options %s\n", argv[2]);

		/*
		 * If present, mount rootfs with passed options.
		 * Example F2FS filesystem with compress_algorithm option.
		 */
		mount("/dev/root", "/", NULL, MS_NOATIME | MS_REMOUNT,
		      argc < 3 ? 0 : argv[2]);
	}

	/* Check for extroot config in rootfs before even trying rootfs_data */
	if (!mount_extroot("")) {
		ULOG_NOTE("switched to extroot\n");
		return 0;
	}

	/* There isn't extroot, so just try to mount "rootfs_data" */
	volume_init(data);
	switch (volume_identify(data)) {
	case FS_NONE:
		ULOG_WARN("no usable overlay filesystem found, using tmpfs overlay\n");
		return ramoverlay();

	case FS_DEADCODE:
		/*
		 * Filesystem isn't ready yet and we are in the preinit, so we
		 * can't afford waiting for it. Use tmpfs for now and handle it
		 * properly in the "done" call.
		 */
		ULOG_NOTE("jffs2 not ready yet, using temporary tmpfs overlay\n");
		return ramoverlay();

	case FS_EXT4:
	case FS_F2FS:
	case FS_JFFS2:
	case FS_UBIFS:
		mount_overlay(data);
		break;

	case FS_SNAPSHOT:
		mount_snapshot(data);
		break;
	}

	return 0;
}

static int
stop(int argc, char *argv[1])
{
	if (!getenv("SHUTDOWN"))
		return -1;

	return 0;
}

/*
 * Called at the end of init, it can wait for filesystem if needed.
 */
static int
done(int argc, char *argv[1])
{
	struct volume *v = volume_find("rootfs_data");

	if (!v)
		return -1;

	switch (volume_identify(v)) {
	case FS_NONE:
	case FS_DEADCODE:
		return jffs2_switch(v);

	case FS_EXT4:
	case FS_F2FS:
	case FS_JFFS2:
	case FS_UBIFS:
		fs_state_set("/overlay", FS_STATE_READY);
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2 || !strcmp(argv[1], "start"))
		return start(argc, argv);
	if (!strcmp(argv[1], "ram"))
		return ramoverlay();
	if (!strcmp(argv[1], "stop"))
		return stop(argc, argv);
	if (!strcmp(argv[1], "done"))
		return done(argc, argv);
	return -1;
}
