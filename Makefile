# =============================================================================
# Adaptive XDP/eBPF Firewall
#
#   make            build everything
#   make deps       install system packages (needs sudo)
#   make model      train the Random Forest on synthetic data
#   make test       run the offline pipeline test (no root needed)
#   make testbed    create the network-namespace testbed (needs sudo)
#   make load       load and attach the firewall (needs sudo)
#   make unload     detach and remove pins (needs sudo)
#   make demo       set up everything and open the tmux demo layout
#   make clean      remove build artefacts
# =============================================================================

CLANG      ?= clang
CC         ?= gcc
IFACE      ?= veth-fw
NS         ?= fwtest

# The kernel's asm/ headers live in an arch-specific include directory.
# Without this -I, clang -target bpf cannot resolve <asm/types.h> and the
# build fails in a confusing way deep inside <linux/ip.h>.
ARCH       := $(shell uname -m)
ARCH_INC   := /usr/include/$(ARCH)-linux-gnu
TARGET_ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; \
                                       s/armv.*/arm/; s/ppc64le/powerpc/; \
                                       s/s390x/s390/; s/riscv64/riscv/')

BPF_SRC    := bpf/firewall.bpf.c
BPF_OBJ    := bpf/firewall.bpf.o
LOADER_SRC := src/loader.c
LOADER_BIN := bin/fwload

# -g is REQUIRED, not a debugging nicety: it emits the BTF type information
# that the kernel needs in order to allow a bpf_spin_lock inside a map value,
# and that libbpf needs to set up the maps. Drop it and the load fails with a
# mystifying "map_check_btf" error.
BPF_CFLAGS := -g -O2 -Wall -target bpf \
              -D__TARGET_ARCH_$(TARGET_ARCH) \
              -I$(ARCH_INC) -Ibpf

LOADER_CFLAGS := -O2 -Wall -Wextra -Ibpf
LOADER_LDLIBS := -lbpf -lelf -lz

.PHONY: all deps model test testbed teardown load unload reload demo \
        check-schema clean help

all: $(BPF_OBJ) $(LOADER_BIN)
	@echo ""
	@echo "build complete."
	@echo "  next:  sudo ./bench/setup_netns.sh"
	@echo "         sudo ./bin/fwload -i $(IFACE)"

# --- eBPF data plane ---------------------------------------------------------
$(BPF_OBJ): $(BPF_SRC) bpf/common.h
	@echo "  CLANG-BPF  $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@# Strip DWARF but KEEP BTF. llvm-strip is optional; skip it silently if
	@# the LLVM tools are not installed, since the object works either way.
	@which llvm-strip >/dev/null 2>&1 && llvm-strip -g $@ || true
	@echo "             $$(stat -c%s $@) bytes"

# --- userspace loader --------------------------------------------------------
$(LOADER_BIN): $(LOADER_SRC) bpf/common.h | bin
	@echo "  CC         $@"
	@$(CC) $(LOADER_CFLAGS) -o $@ $< $(LOADER_LDLIBS)

bin:
	@mkdir -p bin

# --- dependencies ------------------------------------------------------------
deps:
	@./scripts/install_deps.sh

# --- schema consistency ------------------------------------------------------
# Verifies the C structs and the Python format strings still agree. Run this
# after ANY change to bpf/common.h.
check-schema:
	@echo "checking C struct sizes..."
	@printf '#include <linux/bpf.h>\n#include <linux/types.h>\n#include <stdio.h>\n#include "bpf/common.h"\nint main(void){printf("%%zu %%zu %%zu %%zu %%zu\\n",sizeof(struct lpm_key),sizeof(struct allow_val),sizeof(struct block_val),sizeof(struct src_state),sizeof(struct fw_config));adaptfw_check_sizes();return 0;}\n' > /tmp/_szchk.c
	@$(CC) -I. -o /tmp/_szchk /tmp/_szchk.c && /tmp/_szchk
	@echo "checking Python mirrors..."
	@python3 -c "from control import schema; print('schema.py OK')"
	@rm -f /tmp/_szchk /tmp/_szchk.c

# --- model -------------------------------------------------------------------
model:
	python3 -m control.train --synthetic

# --- tests -------------------------------------------------------------------
test:
	python3 tests/test_pipeline.py

# --- testbed -----------------------------------------------------------------
testbed:
	sudo ./bench/setup_netns.sh

teardown:
	sudo ./bench/teardown_netns.sh

# --- load / unload -----------------------------------------------------------
load: $(BPF_OBJ) $(LOADER_BIN)
	sudo ./$(LOADER_BIN) -i $(IFACE)

unload:
	sudo ./$(LOADER_BIN) -i $(IFACE) -u

# Rebuild and reload. Note the unload first: libbpf refuses to reuse a pinned
# map whose value size changed, so editing common.h without unloading gives a
# confusing load failure.
reload: unload all load

# --- demo --------------------------------------------------------------------
demo: all model
	sudo ./bench/setup_netns.sh
	sudo ./$(LOADER_BIN) -i $(IFACE)
	sudo python3 -m control.fwctl allow add 10.10.1.2
	@echo ""
	@echo "ready. opening the tmux demo layout; follow docs/DEMO.md"
	@./bench/demo_tmux.sh

clean:
	rm -f $(BPF_OBJ) $(LOADER_BIN)
	rm -rf bin __pycache__ control/__pycache__ tests/__pycache__
	@echo "cleaned (models/, data/ and results/ left alone)"

help:
	@sed -n '2,16p' $(MAKEFILE_LIST)
