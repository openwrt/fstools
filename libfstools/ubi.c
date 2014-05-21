/*
 * Copyright (C) 2014 Daniel Golle <daniel@makrotopia.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "libfstools.h"
#include "volume.h"

/* could use libubi-tiny instead, but already had the code directly reading
 * from sysfs */
char *ubi_dir_name = "/sys/devices/virtual/ubi";

struct ubi_priv {
	int		ubi_num;
	int		ubi_volidx;
};

static struct driver ubi_driver;

static unsigned int
read_uint_from_file(char *dirname, char *filename, unsigned int *i)
{
	FILE *f;
	char fname[128];
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

static char
*read_string_from_file(char *dirname, char *filename)
{
	FILE *f;
	char fname[128];
	char buf[128];
	int i;
	char *str;

	snprintf(fname, sizeof(fname), "%s/%s", dirname, filename);

	f = fopen(fname, "r");
	if (!f)
		return NULL;

	if (fgets(buf, 128, f) == NULL)
		return NULL;

	i = strlen(buf);
	do
		buf[i--]='\0';
	while (buf[i] == '\n');

	str = strdup(buf);
	fclose(f);
	return str;
}

static unsigned int
test_open(char *filename)
{
	FILE *f;

	f = fopen(filename, "r");
	if (!f)
		return 0;

	fclose(f);
	return 1;
}

static int ubi_volume_init(struct volume *v)
{
	char voldir[40], voldev[32], *volname;
	struct ubi_priv *p;
	unsigned int volsize;

	p = (struct ubi_priv*)v->priv;

	snprintf(voldir, sizeof(voldir), "%s/ubi%u/ubi%u_%u",
		ubi_dir_name, p->ubi_num, p->ubi_num, p->ubi_volidx);

	snprintf(voldev, sizeof(voldev), "/dev/ubi%u_%u",
		p->ubi_num, p->ubi_volidx);

	volname = read_string_from_file(voldir, "name");
	if (!volname)
		return -1;

	if (read_uint_from_file(voldir, "data_bytes", &volsize))
		return -1;

	v->name = volname;
	v->type = UBIVOLUME;
	v->size = volsize;
	v->blk = strdup(voldev);

	return 0;
}


static int ubi_volume_match(struct volume *v, char *name, int ubi_num, int volidx)
{
	char voldir[40], volblkdev[40], *volname;
	struct ubi_priv *p;

	snprintf(voldir, sizeof(voldir), "%s/ubi%u/ubi%u_%u",
		ubi_dir_name, ubi_num, ubi_num, volidx);

	snprintf(volblkdev, sizeof(volblkdev), "/dev/ubiblock%u_%u",
		ubi_num, volidx);

	/* skip if ubiblock device exists */
	if (test_open(volblkdev))
		return -1;

	volname = read_string_from_file(voldir, "name");

	if (strncmp(name, volname, strlen(volname) + 1))
		return -1;

	p = calloc(1, sizeof(struct ubi_priv));
	if (!p)
		return -1;

	v->priv = p;
	v->drv = &ubi_driver;
	p->ubi_num = ubi_num;
	p->ubi_volidx = volidx;

	return ubi_volume_init(v);
}

static int ubi_part_match(struct volume *v, char *name, unsigned int ubi_num)
{
	unsigned int i, volumes_count;
	char devdir[80];

	snprintf(devdir, sizeof(devdir), "%s/ubi%u",
		ubi_dir_name, ubi_num);

	if (read_uint_from_file(devdir, "volumes_count", &volumes_count))
		return -1;

	for (i=0;i<volumes_count;i++) {
		if (!ubi_volume_match(v, name, ubi_num, i)) {
			return 0;
		}
	}

	return -1;
}

static int ubi_volume_find(struct volume *v, char *name)
{
	DIR *ubi_dir;
	struct dirent *ubi_dirent;
	unsigned int ubi_num;
	int ret = -1;

	if (find_filesystem("ubifs"))
		return ret;

	ubi_dir = opendir(ubi_dir_name);
	/* check for os ubi support */
	if (!ubi_dir)
		return ret;

	/* probe ubi devices and volumes */
	while ((ubi_dirent = readdir(ubi_dir)) != NULL) {
		if (ubi_dirent->d_name[0] == '.')
			continue;

		sscanf(ubi_dirent->d_name, "ubi%u", &ubi_num);
		if (!ubi_part_match(v, name, ubi_num)) {
			ret = 0;
			break;
		};
	}
	closedir(ubi_dir);
	return ret;
}

static int ubi_volume_identify(struct volume *v)
{
	return FS_UBIFS;
}

static struct driver ubi_driver = {
	.name = "ubi",
	.find = ubi_volume_find,
	.init = ubi_volume_init,
	.identify = ubi_volume_identify,
};

DRIVER(ubi_driver);
