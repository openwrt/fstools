// SPDX-License-Identifier: GPL-2.0-or-later

#include "common.h"

#define BUFLEN 64

struct devpath {
	char prefix[5];
	char device[11];
};

struct partname_volume {
	struct volume v;
	union {
		char devpathstr[16];
		struct devpath devpath;
	} dev;

	union {
		char devpathstr[16];
		struct devpath devpath;
	} parent_dev;
};

static struct driver partname_driver;

static int partname_volume_identify(struct volume *v)
{
	struct partname_volume *p = container_of(v, struct partname_volume, v);
	int ret = FS_NONE;
	FILE *f;

	f = fopen(p->dev.devpathstr, "r");
	if (!f)
		return ret;

	ret = block_file_identify(f, 0);

	fclose(f);

	return ret;
}

static int partname_volume_init(struct volume *v)
{
	struct partname_volume *p = container_of(v, struct partname_volume, v);
	char voldir[BUFLEN];
	unsigned int volsize;

	snprintf(voldir, sizeof(voldir), "%s/%s", block_dir_name, p->dev.devpath.device);

	if (read_uint_from_file(voldir, "size", &volsize))
		return -1;

	v->type = BLOCKDEV;
	v->size = volsize << 9; /* size is returned in sectors of 512 bytes */
	v->blk = p->dev.devpathstr;

	return block_volume_format(v, 0, p->parent_dev.devpathstr);
}

static char *rootdevname(char *devpath) {
	int l;

	l = strlen(devpath) - 1;

	/* strip partition suffix from root=/dev/... string */
	while (l > 0 && (devpath[l] >= '0' && devpath[l] <= '9'))
		--l;

	if (devpath[l] != 'p')
		++l;

	devpath[l] = '\0';

	return basename(devpath);
}

static struct volume *partname_volume_find(char *name)
{
	struct partname_volume *p;
	char ueventgstr[BUFLEN];
	char namebuf[BUFLEN];
	char rootparam[BUFLEN];
	char *rootdev = NULL, *devname, *tmp;
	int j;
	bool found = false;
	bool allow_fallback = false;
	bool has_root = false;
	glob_t gl;

	if (get_var_from_file("/proc/cmdline", "fstools_ignore_partname", rootparam, sizeof(rootparam))) {
		if (!strcmp("1", rootparam))
			return NULL;
	}

	/*
	 * Some device may contains a GPT partition named rootfs_data that may not be suitable.
	 * To save from regression with old implementation that doesn't use fstools_ignore_partname to
	 * explicitly say that that partname scan should be ignored, make explicit that scanning each
	 * partition should be done by providing fstools_partname_fallback_scan=1 and skip partname scan
	 * in every other case.
	 */
	if (get_var_from_file("/proc/cmdline", "fstools_partname_fallback_scan", rootparam, sizeof(rootparam))) {
		if (!strcmp("1", rootparam))
			allow_fallback = true;
	}

	if (get_var_from_file("/proc/cmdline", "root", rootparam, sizeof(rootparam)))
		has_root = true;

	if (has_root && rootparam[0] == '/') {
		rootdev = rootdevname(rootparam);
		/* find partition on same device as rootfs */
		snprintf(ueventgstr, sizeof(ueventgstr), "%s/%s/*/uevent", block_dir_name, rootdev);
	} else {
		/* For compatibility, devices with root= params must explicitly opt into this fallback. */
		if (has_root && !allow_fallback)
			return NULL;

		/* no useful 'root=' kernel cmdline parameter, find on any block device */
		snprintf(ueventgstr, sizeof(ueventgstr), "%s/*/uevent", block_dir_name);
	}

	if (!glob(ueventgstr, GLOB_NOESCAPE, NULL, &gl))
		for (j = 0; j < gl.gl_pathc; j++) {
			if (!get_var_from_file(gl.gl_pathv[j], "PARTNAME", namebuf, sizeof(namebuf)))
				continue;
			if (!strncmp(namebuf, name, sizeof(namebuf))) {
				found = 1;
				break;
			}
		}

	if (!found)
		return NULL;

	devname = gl.gl_pathv[j];
	tmp = strrchr(devname, '/');
	if (!tmp)
		return NULL;

	*tmp = '\0';
	devname = strrchr(devname, '/') + 1;

	p = calloc(1, sizeof(*p));
	memcpy(p->dev.devpath.prefix, "/dev/", sizeof(p->dev.devpath.prefix));
	strncpy(p->dev.devpath.device, devname, sizeof(p->dev.devpath.device) - 1);
	p->dev.devpath.device[sizeof(p->dev.devpath.device)-1] = '\0';

	memcpy(p->parent_dev.devpath.prefix, "/dev/", sizeof(p->parent_dev.devpath.prefix));
	if (rootdev)
		strncpy(p->parent_dev.devpath.device, rootdev, sizeof(p->parent_dev.devpath.device) - 1);
	else
		strncpy(p->parent_dev.devpath.device, rootdevname(devname), sizeof(p->parent_dev.devpath.device) - 1);

	p->parent_dev.devpath.device[sizeof(p->parent_dev.devpath.device)-1] = '\0';

	p->v.drv = &partname_driver;
	p->v.blk = p->dev.devpathstr;
	p->v.name = name;

	return &p->v;
}

static struct driver partname_driver = {
	.name = "partname",
	.priority = 25,
	.find = partname_volume_find,
	.init = partname_volume_init,
	.identify = partname_volume_identify,
};

DRIVER(partname_driver);
