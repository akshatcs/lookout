// SPDX-License-Identifier: GPL-2.0
/*
 * loader.c -- loads the XDP firewall into the kernel and pins its maps.
 *
 * ============================================================================
 * WHAT THIS DOES AND WHY IT EXITS IMMEDIATELY
 * ============================================================================
 * Run once, this program:
 *   1. opens bpf/firewall.bpf.o (the compiled eBPF object)
 *   2. tells libbpf where to PIN each map, under /sys/fs/bpf/adaptfw/
 *   3. loads the program -- this is where the verifier runs
 *   4. writes a starting configuration into the config map
 *   5. attaches the program to a network interface
 *   6. exits
 *
 * Step 6 is intersting. The firewall keeps running after the loader is
 * gone, because:
 *   - the network device itself holds a reference to the attached program, so
 *     the program is not freed when our file descriptors close;
 *   - the maps are pinned into bpffs, which is a filesystem reference, so they
 *     survive too.
 *
 * That is the whole reason we pin. It is what lets a completely separate
 * process -- the Python control plane -- attach to the same maps later by
 * path, and it is what makes the "kill the control plane, firewall keeps
 * enforcing" moment in the demo work.
 *
 * To tear everything down again: ./bin/fwload -i <iface> -u
 *
 * ============================================================================
 * NATIVE vs SKB MODE
 * ============================================================================
 * XDP has two attachment modes:
 *   native (DRV)  -- runs inside the NIC driver, before sk_buff allocation.
 *                    This is the fast path and the point of the project.
 *   generic (SKB) -- a fallback the core network stack provides for drivers
 *                    with no XDP support. It runs AFTER sk_buff allocation, so
 *                    it gives us the same semantics at much lower speed.
 *
 * In a VM, whether native works depends entirely on the virtual NIC driver.
 * virtio-net supports it; the emulated e1000 does not. veth does. We default
 * to mode "auto": try native, and if the kernel refuses, fall back to generic
 * and display it, because a benchmark run in generic mode measures
 * something quite different and we must not confuse the two.
 */

#include <errno.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common.h"

/*
 * libbpf API compatibility.
 *
 * bpf_xdp_attach()/bpf_xdp_detach() arrived in libbpf 0.7. Ubuntu 22.04 ships
 * libbpf 0.5, Ubuntu 24.04 ships 1.x. Rather than demand a specific distro we
 * detect the version and fall back to the older bpf_set_link_xdp_fd().
 */
#if defined(__has_include)
#  if __has_include(<bpf/libbpf_version.h>)
#    include <bpf/libbpf_version.h>
#  endif
#endif

#if defined(LIBBPF_MAJOR_VERSION) && \
	(LIBBPF_MAJOR_VERSION > 0 || \
	 (LIBBPF_MAJOR_VERSION == 0 && LIBBPF_MINOR_VERSION >= 7))
#  define XDP_ATTACH(ifx, fd, flags) bpf_xdp_attach((ifx), (fd), (flags), NULL)
#  define XDP_DETACH(ifx, flags)     bpf_xdp_detach((ifx), (flags), NULL)
#else
#  define XDP_ATTACH(ifx, fd, flags) bpf_set_link_xdp_fd((ifx), (fd), (flags))
#  define XDP_DETACH(ifx, flags)     bpf_set_link_xdp_fd((ifx), -1, (flags))
#endif

#define PROG_NAME "xdp_firewall"

static const char *map_names[] = {
	"allowlist", "blocklist", "srcstate", "stats", "config",
};
#define N_MAPS (sizeof(map_names) / sizeof(map_names[0]))

struct opts {
	const char *iface;
	const char *obj_path;
	const char *pin_dir;
	const char *mode;
	int unload;
	int verbose;
	__u64 rate_pps;
	__u64 burst_pkts;
};

static void usage(const char *argv0)
{
	fprintf(stderr,
"Usage: %s -i <interface> [options]\n"
"\n"
"  -i, --iface <name>     interface to attach to (required)\n"
"  -o, --obj <path>       BPF object file (default bpf/firewall.bpf.o)\n"
"  -p, --pin-dir <path>   bpffs pin directory (default %s)\n"
"  -m, --mode <m>         auto | native | skb   (default auto)\n"
"  -r, --rate <pps>       initial per-source rate limit (default 20000)\n"
"  -b, --burst <pkts>     initial bucket capacity   (default 40000)\n"
"  -u, --unload           detach the program and remove all pins\n"
"  -v, --verbose          print libbpf debug output (verifier log lives here)\n"
"  -h, --help             this message\n"
"\n"
"Examples:\n"
"  sudo %s -i veth-fw                 # load and attach\n"
"  sudo %s -i veth-fw -m skb -v       # force generic mode, verbose\n"
"  sudo %s -i veth-fw -u              # unload everything\n",
		argv0, ADAPTFW_PIN_DIR, argv0, argv0, argv0);
}

/* libbpf prints its messages, including the full verifier log, through this
 * callback. Without -v we suppress DEBUG but always let WARN through -- if the
 * verifier rejects the program, the reason appears here and nowhere else. */
static int verbose_flag;

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose_flag)
		return 0;
	return vfprintf(stderr, fmt, args);
}

/* Kernels before 5.11 charge BPF map memory against RLIMIT_MEMLOCK, which
 * defaults to a few hundred KB -- far too small for our 4 MiB srcstate map.
 * Raising it is harmless on newer kernels that use memcg accounting instead. */
static void bump_memlock_rlimit(void)
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &r))
		fprintf(stderr,
			"warning: could not raise RLIMIT_MEMLOCK (%s); "
			"map creation may fail on kernels < 5.11\n",
			strerror(errno));
}

/* bpffs must be mounted before anything can be pinned into it. On most
 * systems systemd has already done this. */
static int ensure_pin_dir(const char *dir)
{
	struct stat st;

	if (stat("/sys/fs/bpf", &st) != 0) {
		fprintf(stderr,
			"error: /sys/fs/bpf does not exist. Mount bpffs with:\n"
			"       sudo mount -t bpf bpf /sys/fs/bpf\n");
		return -1;
	}

	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "error: mkdir(%s): %s\n", dir, strerror(errno));
		return -1;
	}
	return 0;
}

static int remove_pins(const char *dir)
{
	char path[PATH_MAX];
	size_t i;
	int removed = 0;

	for (i = 0; i < N_MAPS; i++) {
		snprintf(path, sizeof(path), "%s/%s", dir, map_names[i]);
		if (unlink(path) == 0) {
			removed++;
		} else if (errno != ENOENT) {
			fprintf(stderr, "warning: unlink(%s): %s\n", path,
				strerror(errno));
		}
	}

	snprintf(path, sizeof(path), "%s/%s", dir, PROG_NAME);
	if (unlink(path) == 0)
		removed++;

	if (rmdir(dir) != 0 && errno != ENOENT && errno != ENOTEMPTY)
		fprintf(stderr, "warning: rmdir(%s): %s\n", dir, strerror(errno));

	return removed;
}

static int do_unload(const struct opts *o)
{
	int ifindex = if_nametoindex(o->iface);
	int n;

	if (!ifindex) {
		fprintf(stderr, "error: no such interface '%s'\n", o->iface);
		return 1;
	}

	/* Detach from every mode. Passing flags of 0 lets the kernel remove
	 * whichever program is attached, regardless of how it got there. */
	if (XDP_DETACH(ifindex, 0) && errno != ENOENT)
		fprintf(stderr, "warning: detach from %s: %s\n", o->iface,
			strerror(errno));
	else
		printf("detached XDP program from %s\n", o->iface);

	n = remove_pins(o->pin_dir);
	printf("removed %d pinned object(s) from %s\n", n, o->pin_dir);
	printf("unload complete\n");
	return 0;
}

/* Seed the config map so the firewall is immediately usable, with or without
 * the Python control plane ever being started. This matters: milestone 1 must
 * be demonstrable on its own. */
static int write_initial_config(struct bpf_object *obj, const struct opts *o)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, "config");
	struct fw_config cfg;
	__u32 key = 0;
	int fd;

	if (!map) {
		fprintf(stderr, "error: config map not found in object\n");
		return -1;
	}
	fd = bpf_map__fd(map);

	memset(&cfg, 0, sizeof(cfg));
	cfg.rate_pps = o->rate_pps;
	cfg.burst_pkts = o->burst_pkts;
	cfg.features = FEAT_DEFAULT;
	cfg.aggressiveness = 0;
	cfg.default_action = XDP_PASS;

	if (bpf_map_update_elem(fd, &key, &cfg, BPF_ANY)) {
		fprintf(stderr, "error: writing config: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int attach_with_mode(int ifindex, int prog_fd, const char *mode,
			    const char **used)
{
	int err;

	if (!strcmp(mode, "skb")) {
		err = XDP_ATTACH(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
		*used = "generic/SKB";
		return err;
	}

	if (!strcmp(mode, "native")) {
		err = XDP_ATTACH(ifindex, prog_fd, XDP_FLAGS_DRV_MODE);
		*used = "native/DRV";
		return err;
	}

	/* auto: prefer native, fall back to generic. */
	err = XDP_ATTACH(ifindex, prog_fd, XDP_FLAGS_DRV_MODE);
	if (!err) {
		*used = "native/DRV";
		return 0;
	}

	fprintf(stderr,
		"note: native XDP attach failed (%s); falling back to generic.\n"
		"      Generic mode runs after sk_buff allocation and is much\n"
		"      slower -- fine for functional demos, but mention it\n"
		"      if we benchmark in this mode.\n",
		strerror(-err ? -err : errno));

	err = XDP_ATTACH(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
	*used = "generic/SKB";
	return err;
}

int main(int argc, char **argv)
{
	struct opts o = {
		.iface = NULL,
		.obj_path = "bpf/firewall.bpf.o",
		.pin_dir = ADAPTFW_PIN_DIR,
		.mode = "auto",
		.unload = 0,
		.verbose = 0,
		.rate_pps = 20000,
		.burst_pkts = 40000,
	};
	static const struct option longopts[] = {
		{ "iface",   required_argument, 0, 'i' },
		{ "obj",     required_argument, 0, 'o' },
		{ "pin-dir", required_argument, 0, 'p' },
		{ "mode",    required_argument, 0, 'm' },
		{ "rate",    required_argument, 0, 'r' },
		{ "burst",   required_argument, 0, 'b' },
		{ "unload",  no_argument,       0, 'u' },
		{ "verbose", no_argument,       0, 'v' },
		{ "help",    no_argument,       0, 'h' },
		{ 0, 0, 0, 0 }
	};
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *map;
	char path[PATH_MAX];
	const char *mode_used = "?";
	int ifindex, prog_fd, err, c;

	while ((c = getopt_long(argc, argv, "i:o:p:m:r:b:uvh", longopts, NULL)) != -1) {
		switch (c) {
		case 'i': o.iface = optarg; break;
		case 'o': o.obj_path = optarg; break;
		case 'p': o.pin_dir = optarg; break;
		case 'm': o.mode = optarg; break;
		case 'r': o.rate_pps = strtoull(optarg, NULL, 10); break;
		case 'b': o.burst_pkts = strtoull(optarg, NULL, 10); break;
		case 'u': o.unload = 1; break;
		case 'v': o.verbose = 1; verbose_flag = 1; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	if (!o.iface) {
		fprintf(stderr, "error: -i/--iface is required\n\n");
		usage(argv[0]);
		return 1;
	}

	if (strcmp(o.mode, "auto") && strcmp(o.mode, "native") &&
	    strcmp(o.mode, "skb")) {
		fprintf(stderr, "error: --mode must be auto, native or skb\n");
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr,
			"error: loading BPF programs requires root (or CAP_BPF +\n"
			"       CAP_NET_ADMIN). Re-run with sudo.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	if (o.unload)
		return do_unload(&o);

	ifindex = if_nametoindex(o.iface);
	if (!ifindex) {
		fprintf(stderr, "error: no such interface '%s'\n", o.iface);
		return 1;
	}

	bump_memlock_rlimit();

	if (ensure_pin_dir(o.pin_dir))
		return 1;

	/* --- open ------------------------------------------------------------
	 * "Open" parses the ELF and builds libbpf's in-memory model of the
	 * programs and maps. Nothing has entered the kernel yet, which is
	 * exactly why we can set pin paths at this stage. */
	obj = bpf_object__open_file(o.obj_path, NULL);
	if (!obj || libbpf_get_error(obj)) {
		fprintf(stderr,
			"error: opening '%s': %s\n"
			"       Did you run `make` first?\n",
			o.obj_path, strerror(errno));
		return 1;
	}

	/* --- set pin paths ---------------------------------------------------
	 * Setting a pin path before load makes libbpf do two useful things:
	 *   - if the pin already exists, REUSE that map instead of creating a
	 *     new one (so reloading the program keeps the blocklist);
	 *   - if it does not, create the map and pin it after load.
	 *
	 * The reuse behaviour has one sharp edge worth knowing: if we changed
	 * a struct in common.h, the existing pinned map has the old value size
	 * and libbpf will refuse to reuse it. Run with -u first in that case.
	 * The error message says "map ... has ... value_size ..." and is
	 * otherwise quite mystifying. */
	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);

		snprintf(path, sizeof(path), "%s/%s", o.pin_dir, name);
		err = bpf_map__set_pin_path(map, path);
		if (err) {
			fprintf(stderr, "error: set_pin_path(%s): %s\n", name,
				strerror(-err));
			goto cleanup;
		}
	}

	/* --- load ------------------------------------------------------------
	 * THIS is where the verifier runs. If the program is rejected, the
	 * reason is in the libbpf output above -- re-run with -v to see the
	 * complete instruction-by-instruction log. */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr,
			"error: loading BPF object: %s\n"
			"       Re-run with -v for the full verifier log.\n"
			"       If you changed common.h, run with -u first to\n"
			"       clear stale pinned maps.\n",
			strerror(-err));
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, PROG_NAME);
	if (!prog) {
		fprintf(stderr, "error: program '%s' not found in object\n",
			PROG_NAME);
		err = -1;
		goto cleanup;
	}
	prog_fd = bpf_program__fd(prog);

	if (write_initial_config(obj, &o)) {
		err = -1;
		goto cleanup;
	}

	/* Pin the program too. Not strictly required, but it makes the program
	 * show up under a readable name and gives the demo something concrete
	 * to point at with `ls /sys/fs/bpf/adaptfw/`. */
	snprintf(path, sizeof(path), "%s/%s", o.pin_dir, PROG_NAME);
	unlink(path); /* ignore failure; may not exist */
	if (bpf_program__pin(prog, path))
		fprintf(stderr, "warning: could not pin program: %s\n",
			strerror(errno));

	/* --- attach ----------------------------------------------------------*/
	err = attach_with_mode(ifindex, prog_fd, o.mode, &mode_used);
	if (err) {
		fprintf(stderr,
			"error: attaching to %s: %s\n"
			"       If this says 'Device or resource busy', another XDP\n"
			"       program is already attached. Run with -u first.\n",
			o.iface, strerror(-err ? -err : errno));
		goto cleanup;
	}

	printf("=========================================================\n");
	printf(" Adaptive XDP/eBPF firewall loaded\n");
	printf("=========================================================\n");
	printf("  interface      : %s (ifindex %d)\n", o.iface, ifindex);
	printf("  attach mode    : %s\n", mode_used);
	printf("  pinned maps    : %s/\n", o.pin_dir);
	printf("  rate limit     : %llu pps/source, burst %llu\n",
	       (unsigned long long)o.rate_pps, (unsigned long long)o.burst_pkts);
	printf("  features       : allowlist blocklist proto-sanity "
	       "ratelimit state-tracking\n");
	printf("\n");
	printf("The program stays attached after this process exits.\n");
	printf("Next:  sudo python3 -m control.controller --iface %s\n", o.iface);
	printf("Stop:  sudo %s -i %s -u\n", argv[0], o.iface);

	/* Deliberately do NOT destroy the object -- see the header comment.
	 * Closing our fds is fine; the netdev and the pins hold the real
	 * references. */
	return 0;

cleanup:
	if (obj)
		bpf_object__close(obj);
	return 1;
}
