// SPDX-License-Identifier: GPL-2.0-or-later

#include "common.h"

#define BUFLEN 64
#define DEVPATHSTR_SIZE 15

static const char *const fit0 = "/dev/fit0";
static const char *const fitrw = "/dev/fitrw";

struct devpath {
	char prefix[5];
	char device[11];
};

struct fit_volume {
	struct volume v;
	union {
		char devpathstr[DEVPATHSTR_SIZE+1];
		struct devpath devpath;
	} dev;
};

static struct driver fit_driver;

static int fit_volume_identify(struct volume *v)
{
	struct fit_volume *p = container_of(v, struct fit_volume, v);
	int ret = FS_NONE;
	FILE *f;

	f = fopen(p->dev.devpathstr, "r");
	if (!f)
		return ret;

	ret = block_file_identify(f, 0);

	fclose(f);

	return ret;
}

static int fit_volume_init(struct volume *v)
{
	struct fit_volume *p = container_of(v, struct fit_volume, v);
	char voldir[BUFLEN];
	unsigned int volsize;

	snprintf(voldir, sizeof(voldir), "%s/%s", block_dir_name, p->dev.devpath.device);

	if (read_uint_from_file(voldir, "size", &volsize))
		return -1;

	v->type = BLOCKDEV;
	v->size = volsize << 9; /* size is returned in sectors of 512 bytes */
	v->blk = p->dev.devpathstr;

	return block_volume_format(v, 0, p->dev.devpathstr);
}

static struct volume *fit_volume_find(char *name)
{
	struct fit_volume *p;
	struct stat buf;
	const char *fname;
	int ret;

	if (!strcmp(name, "rootfs"))
		fname = fit0;
	else if (!strcmp(name, "rootfs_data"))
		fname = fitrw;
	else
		return NULL;

	ret = stat(fname, &buf);
	if (ret)
		return NULL;

	p = calloc(1, sizeof(struct fit_volume));
	if (!p)
		return NULL;

	strncpy(p->dev.devpathstr, fname, DEVPATHSTR_SIZE);
	p->v.drv = &fit_driver;
	p->v.blk = p->dev.devpathstr;
	p->v.name = name;

	return &p->v;
}

static struct driver fit_driver = {
	.name = "fit",
	.priority = 30,
	.find = fit_volume_find,
	.init = fit_volume_init,
	.identify = fit_volume_identify,
};

DRIVER(fit_driver);
