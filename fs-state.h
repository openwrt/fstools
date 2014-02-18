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

#ifndef _FS_STATE_H__
#define _FS_STATE_H__

#include <libubox/list.h>
#include <libubox/blob.h>

enum {
	FS_NONE,
	FS_SNAPSHOT,
	FS_JFFS2,
	FS_DEADCODE,
};

typedef int (*backend_cli_t)(int argc, char **argv);
typedef int (*backend_mount_t)(void);
typedef int (*backend_info_t)(void);

extern char const *extroot_prefix;

struct backend_handler
{
	char		*name;
	char		*desc;
	backend_cli_t	cli;
};

struct backend
{
	struct list_head	list;
	char			*name;
	char			*desc;
	int			num_handlers;
	backend_cli_t		cli;
	backend_mount_t		mount;
	backend_info_t		info;
	struct backend_handler	*handlers;
};

void register_backend(struct backend *);
struct backend* find_backend(char *);
int backend_mount(char *name);

#define BACKEND(x)					\
	static void __attribute__((constructor))	\
	register_##x(void) {				\
		register_backend(&x);			\
	}

int mount_move(char *oldroot, char *newroot, char *dir);
int pivot(char *new, char *old);
int fopivot(char *rw_root, char *ro_root);
int ramoverlay(void);

int find_overlay_mount(char *overlay);
char* find_mount(char *mp);
char* find_mount_point(char *block, char *fs);
int find_filesystem(char *fs);
int find_mtd_block(char *name, char *part, int plen);
int find_mtd_char(char *name, char *part, int plen);

int jffs2_ready(char *mtd);
int jffs2_switch(int argc, char **argv);

int handle_whiteout(const char *dir);
void foreachdir(const char *dir, int (*cb)(const char*));

#endif
