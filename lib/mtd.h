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

#ifndef _FS_MTD_H__
#define _FS_MTD_H__

extern int mtdsize;
extern int erasesize;

int mtd_open(const char *mtd, int block);
int mtd_load(const char *mtd);
void mtd_erase(int fd, int first_block, int num_blocks);
int mtd_unlock(int fd);
int mtd_read_buffer(int fd, void *buf, int offset, int length);
int mtd_write_buffer(int fd, void *buf, int offset, int length);
int mtd_identify(char *mtd);

#endif
