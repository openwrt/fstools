cmake_minimum_required(VERSION 2.6)

PROJECT(fs-tools C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_EXECUTABLE(fs-state fs-state.c
		backend/base.c
		backend/snapshot.c
		backend/extroot.c
		backend/jffs2.c
			lib/mtd.c
		lib/mount.c
		lib/find.c)

TARGET_LINK_LIBRARIES(fs-state ubox)
INSTALL(TARGETS fs-state RUNTIME DESTINATION sbin)

ADD_EXECUTABLE(block block.c
		libblkid-tiny/libblkid-tiny.c
		libblkid-tiny/mkdev.c
		libblkid-tiny/ext.c
		libblkid-tiny/jffs2.c
		libblkid-tiny/vfat.c
		libblkid-tiny/swap.c
		libblkid-tiny/squashfs.c)
TARGET_LINK_LIBRARIES(block uci ubox blobmsg_json)
INSTALL(TARGETS block RUNTIME DESTINATION sbin)
