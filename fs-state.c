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

#include <stdio.h>
#include <string.h>

#include "fs-state.h"

static LIST_HEAD(backends);

void
register_backend(struct backend *b)
{
	list_add(&b->list, &backends);
}

struct backend*
find_backend(char *name)
{
	struct backend *b;

	list_for_each_entry(b, &backends, list)
		if (!strcmp(name, b->name))
			return b;
	return NULL;
}

static void
help(void)
{
	struct backend *b;

	list_for_each_entry(b, &backends, list) {
		int i;

		if (b->desc)
			fprintf(stderr, "-> %s\n", b->name);
		for (i = 0; i < b->num_handlers; i++)
			if (b->handlers[i].desc)
				fprintf(stderr, "--> %s\n", b->handlers[i].name);
	}
}

int
main(int argc, char **argv)
{
	struct backend *b;

	if (argc > 1) list_for_each_entry(b, &backends, list) {
		int i;

		srand(time(NULL));

		if (strcmp(argv[1], b->name))
			continue;

		for (i = 0; i < b->num_handlers; i++)
			if (!strcmp(argv[2], b->handlers[i].name))
				return b->handlers[i].cli(argc - 2, &argv[2]);

		if (b->cli)
			return b->cli(argc - 1, &argv[1]);

		break;
	}

	help();

	return 0;
}
