/*
 * Low-level libblkid probing API
 *
 * Copyright (C) 2008-2009 Karel Zak <kzak@redhat.com>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */

#include <stdlib.h>

#include "libblkid-tiny.h"

struct blkid_struct_probe *blkid_new_probe(void)
{
	struct blkid_struct_probe *pr;

	pr = calloc(1, sizeof(struct blkid_struct_probe));
	if (!pr)
		return NULL;

	return pr;
}

void blkid_free_probe(struct blkid_struct_probe *pr)
{
	if (!pr)
		return;

	free(pr);
}
