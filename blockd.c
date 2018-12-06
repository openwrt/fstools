#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <errno.h>

#include <linux/limits.h>
#include <linux/auto_fs4.h>

#include <libubox/uloop.h>
#include <libubox/vlist.h>
#include <libubox/ulog.h>
#include <libubox/avl-cmp.h>
#include <libubus.h>

#include "libfstools/libfstools.h"

#define	AUTOFS_MOUNT_PATH	"/tmp/run/blockd/"
#define AUTOFS_TIMEOUT		30
#define AUTOFS_EXPIRE_TIMER	(5 * 1000)

struct device {
	struct vlist_node node;
	struct blob_attr *msg;
	char *name;
	char *target;
	int autofs;
	int anon;
};

static struct uloop_fd fd_autofs_read;
static int fd_autofs_write = 0;
static struct ubus_auto_conn conn;
struct blob_buf bb = { 0 };

enum {
	MOUNT_UUID,
	MOUNT_LABEL,
	MOUNT_ENABLE,
	MOUNT_TARGET,
	MOUNT_DEVICE,
	MOUNT_OPTIONS,
	MOUNT_AUTOFS,
	MOUNT_ANON,
	MOUNT_REMOVE,
	__MOUNT_MAX
};

static const struct blobmsg_policy mount_policy[__MOUNT_MAX] = {
	[MOUNT_UUID] = { .name = "uuid", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_LABEL] = { .name = "label", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_DEVICE] = { .name = "device", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_TARGET] = { .name = "target", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_OPTIONS] = { .name = "options", .type = BLOBMSG_TYPE_STRING },
	[MOUNT_ENABLE] = { .name = "enabled", .type = BLOBMSG_TYPE_INT32 },
	[MOUNT_AUTOFS] = { .name = "autofs", .type = BLOBMSG_TYPE_INT32 },
	[MOUNT_ANON] = { .name = "anon", .type = BLOBMSG_TYPE_INT32 },
	[MOUNT_REMOVE] = { .name = "remove", .type = BLOBMSG_TYPE_INT32 },
};

static char*
_find_mount_point(char *device)
{
	char dev[32] = { 0 };

	snprintf(dev, sizeof(dev), "/dev/%s", device);

	return find_mount_point(dev, 0);
}

static int
block(char *cmd, char *action, char *device)
{
	pid_t pid = fork();
	int ret = -1;
	int status;
	char *argv[5] = { 0 };
	int a = 0;

	switch (pid) {
	case -1:
		ULOG_ERR("failed to fork block process\n");
		break;

	case 0:
		argv[a++] = "/sbin/block";
		argv[a++] = cmd;
		argv[a++] = action;
		argv[a++] = device;
		execvp(argv[0], argv);
		ULOG_ERR("failed to spawn %s %s %s\n", *argv, action, device);
		exit(EXIT_FAILURE);

	default:
		waitpid(pid, &status, 0);
		ret = WEXITSTATUS(status);
		if (ret)
			ULOG_ERR("failed to run block. %s/%s\n", action, device);
		break;
	}

	return ret;
}

static void
device_free(struct device *device)
{
	struct blob_attr *data[__MOUNT_MAX];

	blobmsg_parse(mount_policy, __MOUNT_MAX, data,
		      blob_data(device->msg), blob_len(device->msg));

	if (data[MOUNT_AUTOFS] && device->target)
		unlink(device->target);
}

static void
device_add(struct device *device)
{
	struct blob_attr *data[__MOUNT_MAX];
	char path[64];

	blobmsg_parse(mount_policy, __MOUNT_MAX, data,
		      blob_data(device->msg), blob_len(device->msg));

	if (!data[MOUNT_AUTOFS])
		return;

	snprintf(path, sizeof(path), "/tmp/run/blockd/%s",
		 blobmsg_get_string(data[MOUNT_DEVICE]));
	if (symlink(path, device->target))
		ULOG_ERR("failed to symlink %s->%s\n", device->target, path);
}

static int
device_move(struct device *device_o, struct device *device_n)
{
	char path[64];

	if (device_o->autofs != device_n->autofs)
		return -1;

	if (device_o->anon || device_n->anon)
		return -1;

	if (device_o->autofs) {
		unlink(device_o->target);
		snprintf(path, sizeof(path), "/tmp/run/blockd/%s", device_n->name);
		if (symlink(path, device_n->target))
			ULOG_ERR("failed to symlink %s->%s\n", device_n->target, path);
	} else {
		mkdir(device_n->target, 0755);
		if (mount(device_o->target, device_n->target, NULL, MS_MOVE, NULL))
			rmdir(device_n->target);
		else
			rmdir(device_o->target);
	}

	return 0;
}

static void
devices_update_cb(struct vlist_tree *tree, struct vlist_node *node_new,
		  struct vlist_node *node_old)
{
	struct device *device_o = NULL, *device_n = NULL;

	if (node_old)
		device_o = container_of(node_old, struct device, node);

	if (node_new)
		device_n = container_of(node_new, struct device, node);

	if (device_o && device_n) {
		if (device_move(device_o, device_n)) {
			device_free(device_o);
			device_add(device_n);
			if (!device_n->autofs)
				block("mount", NULL, NULL);
		}
	} else if (device_n) {
		device_add(device_n);
	} else {
		device_free(device_o);
	}

	if (device_o)
		free(device_o);
}

VLIST_TREE(devices, avl_strcmp, devices_update_cb, false, false);

static int
block_hotplug(struct ubus_context *ctx, struct ubus_object *obj,
	      struct ubus_request_data *req, const char *method,
	      struct blob_attr *msg)
{
	struct blob_attr *data[__MOUNT_MAX];
	struct device *device;
	struct blob_attr *_msg;
	char *devname, *_name;
	char *target = NULL, *__target;
	char _target[32];

	blobmsg_parse(mount_policy, __MOUNT_MAX, data, blob_data(msg), blob_len(msg));

	if (!data[MOUNT_DEVICE])
		return UBUS_STATUS_INVALID_ARGUMENT;

	devname = blobmsg_get_string(data[MOUNT_DEVICE]);

	if (data[MOUNT_TARGET]) {
		target = blobmsg_get_string(data[MOUNT_TARGET]);
	} else {
		snprintf(_target, sizeof(_target), "/mnt/%s",
			 blobmsg_get_string(data[MOUNT_DEVICE]));
		target = _target;
	}

	if (data[MOUNT_REMOVE])
		device = vlist_find(&devices, devname, device, node);
	else
		device = calloc_a(sizeof(*device), &_msg, blob_raw_len(msg),
				  &_name, strlen(devname) + 1, &__target, strlen(target) + 1);

	if (!device)
		return UBUS_STATUS_UNKNOWN_ERROR;

	vlist_update(&devices);
	if (data[MOUNT_REMOVE]) {
		vlist_delete(&devices, &device->node);
	} else {
		if (data[MOUNT_AUTOFS])
			device->autofs = blobmsg_get_u32(data[MOUNT_AUTOFS]);
		else
			device->autofs = 0;
		if (data[MOUNT_ANON])
			device->anon = blobmsg_get_u32(data[MOUNT_ANON]);
		else
			device->anon = 0;
		device->msg = _msg;
		memcpy(_msg, msg, blob_raw_len(msg));
		device->name = _name;
		strcpy(_name, devname);
		device->target = __target;
		strcpy(__target, target);
		vlist_add(&devices, &device->node, blobmsg_get_string(data[MOUNT_DEVICE]));
	}
	vlist_flush(&devices);

	return 0;
}

static int
block_info(struct ubus_context *ctx, struct ubus_object *obj,
	   struct ubus_request_data *req, const char *method,
	   struct blob_attr *msg)
{
	struct device *device;
	void *a;

	blob_buf_init(&bb, 0);
	a = blobmsg_open_array(&bb, "devices");
	vlist_for_each_element(&devices, device, node) {
		void *t = blobmsg_open_table(&bb, "");
		struct blob_attr *v;
		char *mp;
		int rem;

		blob_for_each_attr(v, device->msg, rem)
			blobmsg_add_blob(&bb, v);

		mp = _find_mount_point(device->name);
		if (mp) {
			blobmsg_add_string(&bb, "mount", mp);
			free(mp);
		}
		blobmsg_close_table(&bb, t);
	}
	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);

	return 0;
}

static const struct ubus_method block_methods[] = {
	UBUS_METHOD("hotplug", block_hotplug, mount_policy),
	UBUS_METHOD_NOARG("info", block_info),
};

static struct ubus_object_type block_object_type =
	UBUS_OBJECT_TYPE("block", block_methods);

static struct ubus_object block_object = {
	.name = "block",
	.type = &block_object_type,
	.methods = block_methods,
	.n_methods = ARRAY_SIZE(block_methods),
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	int ret;

	ret = ubus_add_object(ctx, &block_object);
	if (ret)
		fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
}

static int autofs_umount(void)
{
	umount2(AUTOFS_MOUNT_PATH, MNT_DETACH);
	return 0;
}

static void autofs_read_handler(struct uloop_fd *u, unsigned int events)
{
	union autofs_v5_packet_union pktu;
	const struct autofs_v5_packet *pkt;
	int cmd = AUTOFS_IOC_READY;
	struct stat st;

	while (read(u->fd, &pktu, sizeof(pktu)) == -1) {
		if (errno != EINTR)
			return;
		continue;
	}

	if (pktu.hdr.type != autofs_ptype_missing_indirect) {
		ULOG_ERR("unknown packet type %d\n", pktu.hdr.type);
		return;
	}

	pkt = &pktu.missing_indirect;
        ULOG_ERR("kernel is requesting a mount -> %s\n", pkt->name);
	if (lstat(pkt->name, &st) == -1)
		if (block("autofs", "add", (char *)pkt->name))
			cmd = AUTOFS_IOC_FAIL;

	if (ioctl(fd_autofs_write, cmd, pkt->wait_queue_token) < 0)
		ULOG_ERR("failed to report back to kernel\n");
}

static void autofs_expire(struct uloop_timeout *t)
{
	struct autofs_packet_expire pkt;

	while (ioctl(fd_autofs_write, AUTOFS_IOC_EXPIRE, &pkt) == 0)
		block("autofs", "remove", pkt.name);

	uloop_timeout_set(t, AUTOFS_EXPIRE_TIMER);
}

struct uloop_timeout autofs_expire_timer = {
	.cb = autofs_expire,
};

static int autofs_mount(void)
{
	int autofs_timeout = AUTOFS_TIMEOUT;
	int kproto_version;
	int pipefd[2];
	char source[64];
	char opts[64];

	if (pipe(pipefd) < 0) {
		ULOG_ERR("failed to get kernel pipe\n");
		return -1;
	}

	snprintf(source, sizeof(source), "mountd(pid%u)", getpid());
	snprintf(opts, sizeof(opts), "fd=%d,pgrp=%u,minproto=5,maxproto=5", pipefd[1], (unsigned) getpgrp());
	mkdir(AUTOFS_MOUNT_PATH, 0555);
	if (mount(source, AUTOFS_MOUNT_PATH, "autofs", 0, opts)) {
		ULOG_ERR("unable to mount autofs on %s\n", AUTOFS_MOUNT_PATH);
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}
	close(pipefd[1]);
	fd_autofs_read.fd = pipefd[0];
	fd_autofs_read.cb = autofs_read_handler;
	uloop_fd_add(&fd_autofs_read, ULOOP_READ);

	fd_autofs_write = open(AUTOFS_MOUNT_PATH, O_RDONLY);
	if(fd_autofs_write < 0) {
		autofs_umount();
		ULOG_ERR("failed to open direcory\n");
		return -1;
	}

	ioctl(fd_autofs_write, AUTOFS_IOC_PROTOVER, &kproto_version);
	if (kproto_version != 5) {
		ULOG_ERR("only kernel protocol version 5 is tested. You have %d.\n",
			kproto_version);
		exit(EXIT_FAILURE);
	}
	if (ioctl(fd_autofs_write, AUTOFS_IOC_SETTIMEOUT, &autofs_timeout))
		ULOG_ERR("failed to set autofs timeout\n");

	uloop_timeout_set(&autofs_expire_timer, AUTOFS_EXPIRE_TIMER);

        fcntl(fd_autofs_write, F_SETFD, fcntl(fd_autofs_write, F_GETFD) | FD_CLOEXEC);
        fcntl(fd_autofs_read.fd, F_SETFD, fcntl(fd_autofs_read.fd, F_GETFD) | FD_CLOEXEC);

	return 0;
}

static void blockd_startup(struct uloop_timeout *t)
{
	block("autofs", "start", NULL);
}

struct uloop_timeout startup = {
	.cb = blockd_startup,
};

int main(int argc, char **argv)
{
	ulog_open(ULOG_SYSLOG | ULOG_STDIO, LOG_DAEMON, "blockd");
	uloop_init();

	autofs_mount();

	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);

	uloop_timeout_set(&startup, 1000);

	uloop_run();
	uloop_done();

	autofs_umount();

	vlist_flush_all(&devices);

	return 0;
}
