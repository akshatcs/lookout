// SPDX-License-Identifier: GPL-2.0
/*
 * loader.c - load the XDP program, pin its maps, attach it, exit.
 *
 * The program keeps running after this exits: the network device holds a
 * reference to the attached program and bpffs holds the pinned maps. That
 * is what lets the Python tools open the maps later by path, and why
 * stopping the controller doesn't stop the firewall. The python program runs
 * in user space and can be stopped and restarted without affecting the kernel program.
 *
 *   sudo ./bin/fwload -i veth-fw          load and attach
 *   sudo ./bin/fwload -i veth-fw -u       detach and remove the pins
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"

/* bpf_xdp_attach() appeared in libbpf 0.7. Ubuntu 22.04 ships 0.5. */
#ifdef __has_include
#if __has_include(<bpf/libbpf_version.h>)
#include <bpf/libbpf_version.h>
#endif
#endif
#if defined(LIBBPF_MAJOR_VERSION) && \
	(LIBBPF_MAJOR_VERSION > 0 || LIBBPF_MINOR_VERSION >= 7)
#define XDP_ATTACH(ifx, fd, flags) bpf_xdp_attach(ifx, fd, flags, NULL)
#define XDP_DETACH(ifx)            bpf_xdp_detach(ifx, 0, NULL)
#else
#define XDP_ATTACH(ifx, fd, flags) bpf_set_link_xdp_fd(ifx, fd, flags)
#define XDP_DETACH(ifx)            bpf_set_link_xdp_fd(ifx, -1, 0)
#endif

#define PROG_NAME "xdp_firewall"

static const char *pinned[] = {
	"allowlist", "blocklist", "portrules", "srcstate", "stats", "config",
	PROG_NAME,
};

static int verbose;

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s -i IFACE [options]\n"
		"  -i IFACE   interface to attach to\n"
		"  -o FILE    BPF object (default bpf/firewall.bpf.o)\n"
		"  -m MODE    auto | native | skb (default auto)\n"
		"  -r PPS     initial per-source rate limit (default 20000)\n"
		"  -b PKTS    initial burst (default 40000)\n"
		"  -u         detach and remove pins\n"
		"  -v         show libbpf debug output, including the verifier log\n",
		argv0);
}

static int print_fn(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static int unload(int ifindex, const char *iface)
{
	char path[PATH_MAX];
	size_t i;
	int removed = 0;

	if (XDP_DETACH(ifindex) && errno != ENOENT)
		fprintf(stderr, "warning: detach from %s: %s\n", iface,
			strerror(errno));
	else
		printf("detached XDP program from %s\n", iface);

	for (i = 0; i < sizeof(pinned) / sizeof(pinned[0]); i++) {
		snprintf(path, sizeof(path), "%s/%s", ADAPTFW_PIN_DIR, pinned[i]);
		if (unlink(path) == 0)
			removed++;
	}
	rmdir(ADAPTFW_PIN_DIR);
	printf("removed %d pinned object(s) from %s\n", removed, ADAPTFW_PIN_DIR);
	return 0;
}

/* Try native mode first; fall back to generic, which works everywhere but
 * runs after sk_buff allocation, so don't benchmark in it. */
static const char *attach(int ifindex, int prog_fd, const char *mode)
{
	if (strcmp(mode, "skb") != 0) {
		if (XDP_ATTACH(ifindex, prog_fd, XDP_FLAGS_DRV_MODE) == 0)
			return "native/DRV";
		if (strcmp(mode, "native") == 0)
			return NULL;
		fprintf(stderr, "note: native attach failed, using generic mode "
			"(slower; fine for demos, not for benchmarks)\n");
	}
	if (XDP_ATTACH(ifindex, prog_fd, XDP_FLAGS_SKB_MODE) == 0)
		return "generic/SKB";
	return NULL;
}

int main(int argc, char **argv)
{
	const char *iface = NULL, *obj_path = "bpf/firewall.bpf.o";
	const char *mode = "auto", *mode_used;
	struct fw_config cfg = {
		.rate_pps = 20000,
		.burst_pkts = 40000,
		.features = FEAT_DEFAULT,
		.default_policy = ACTION_ALLOW,
	};
	struct rlimit unlimited = { RLIM_INFINITY, RLIM_INFINITY };
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	char path[PATH_MAX];
	int do_unload = 0, ifindex, err, c;
	__u32 key = 0;

	while ((c = getopt(argc, argv, "i:o:m:r:b:uvh")) != -1) {
		switch (c) {
		case 'i': iface = optarg; break;
		case 'o': obj_path = optarg; break;
		case 'm': mode = optarg; break;
		case 'r': cfg.rate_pps = strtoull(optarg, NULL, 10); break;
		case 'b': cfg.burst_pkts = strtoull(optarg, NULL, 10); break;
		case 'u': do_unload = 1; break;
		case 'v': verbose = 1; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}
	if (!iface) {
		usage(argv[0]);
		return 1;
	}
	if (strcmp(mode, "auto") && strcmp(mode, "native") && strcmp(mode, "skb")) {
		fprintf(stderr, "error: -m must be auto, native or skb\n");
		return 1;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "error: needs root, re-run with sudo\n");
		return 1;
	}
	ifindex = if_nametoindex(iface);
	if (!ifindex) {
		fprintf(stderr, "error: no such interface '%s'\n", iface);
		return 1;
	}

	libbpf_set_print(print_fn);

	if (do_unload)
		return unload(ifindex, iface);

	/* Kernels before 5.11 count map memory against RLIMIT_MEMLOCK. Newer
	 * ones don't care, so a failure here is only worth mentioning in -v. */
	if (setrlimit(RLIMIT_MEMLOCK, &unlimited) && verbose)
		fprintf(stderr, "note: could not raise RLIMIT_MEMLOCK\n");

	if (mkdir(ADAPTFW_PIN_DIR, 0700) && errno != EEXIST) {
		fprintf(stderr, "error: mkdir %s: %s (is bpffs mounted? "
			"sudo mount -t bpf bpf /sys/fs/bpf)\n",
			ADAPTFW_PIN_DIR, strerror(errno));
		return 1;
	}

	obj = bpf_object__open_file(obj_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "error: can't open %s (run make first)\n", obj_path);
		return 1;
	}

	/* With a pin path set before load, libbpf reuses an existing pinned map
	 * instead of creating a new one, so a reload keeps the blocklist. If a
	 * struct in common.h changed, the old pin no longer fits: unload first. */
	bpf_object__for_each_map(map, obj) {
		snprintf(path, sizeof(path), "%s/%s", ADAPTFW_PIN_DIR,
			 bpf_map__name(map));
		bpf_map__set_pin_path(map, path);
	}

	/* The verifier runs here. If it rejects the program, -v shows why. */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "error: load failed: %s\n"
			"  re-run with -v for the verifier log; if you changed "
			"common.h, run with -u first\n", strerror(-err));
		goto fail;
	}

	map = bpf_object__find_map_by_name(obj, "config");
	if (bpf_map_update_elem(bpf_map__fd(map), &key, &cfg, BPF_ANY)) {
		fprintf(stderr, "error: writing config: %s\n", strerror(errno));
		goto fail;
	}

	prog = bpf_object__find_program_by_name(obj, PROG_NAME);
	snprintf(path, sizeof(path), "%s/%s", ADAPTFW_PIN_DIR, PROG_NAME);
	unlink(path);
	bpf_program__pin(prog, path);

	mode_used = attach(ifindex, bpf_program__fd(prog), mode);
	if (!mode_used) {
		fprintf(stderr, "error: attach to %s failed: %s\n"
			"  if the device is busy, another XDP program is attached; "
			"run with -u first\n", iface, strerror(errno));
		goto fail;
	}

	printf("firewall loaded on %s\n", iface);
	printf("  attach mode : %s\n", mode_used);
	printf("  maps        : %s/\n", ADAPTFW_PIN_DIR);
	printf("  rate limit  : %llu pps per source, burst %llu\n",
	       (unsigned long long)cfg.rate_pps,
	       (unsigned long long)cfg.burst_pkts);
	printf("  policy      : default allow (fwctl policy deny to change)\n");
	printf("next: sudo python3 -m control.fwctl status\n");

	/* No cleanup needed: the attached program and the pinned maps hold
	 * their own references, so everything stays loaded after we exit. */
	return 0;

fail:
	bpf_object__close(obj);
	return 1;
}
