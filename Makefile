# Adaptive XDP/eBPF firewall
#
#   make            build the XDP object and the loader
#   make check-schema  C and Python struct layouts agree
#   make test       offline unit tests, no root needed
#   make e2e        full behaviour test against the live testbed (sudo)
#   make testbed    create the veth testbed (sudo)
#   make load       load and attach to $(IFACE) (sudo)
#   make unload     detach and remove the pins (sudo)
#   make reload     unload, rebuild, load (use after editing common.h)
#   make demo       guided demo (scripts/demo.sh)
#   make clean

IFACE ?= veth-fw
ARCH  := $(shell uname -m)
BPF_ARCH := $(shell echo $(ARCH) | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/; s/s390x/s390/; s/riscv64/riscv/')

# -g is required, not just for debugging: it emits the BTF the kernel needs
# before it will allow a bpf_spin_lock inside a map value. The arch include
# dir is where <asm/types.h> lives.
BPF_CFLAGS := -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
              -I/usr/include/$(ARCH)-linux-gnu -Ibpf

.PHONY: all check-schema test e2e testbed teardown load unload reload demo clean

all: bpf/firewall.bpf.o bin/fwload

bpf/firewall.bpf.o: bpf/firewall.bpf.c bpf/common.h
	clang $(BPF_CFLAGS) -c $< -o $@

bin/fwload: src/loader.c bpf/common.h
	@mkdir -p bin
	$(CC) -O2 -Wall -Wextra -Ibpf -o $@ $< -lbpf -lelf -lz

# Both sides check themselves: common.h has _Static_asserts that break the
# BPF build, and firewall.py asserts its format sizes on import.
check-schema: bpf/firewall.bpf.o
	python3 -c "import control.firewall; print('C and Python layouts agree')"

test:
	python3 -m unittest discover -s tests -v

e2e: all
	sudo ./tests/e2e.sh

testbed:
	sudo ./bench/setup_netns.sh

teardown:
	sudo ./bench/teardown_netns.sh

load: all
	sudo ./bin/fwload -i $(IFACE)

unload:
	sudo ./bin/fwload -i $(IFACE) -u

reload: unload all load

demo: all
	sudo ./scripts/demo.sh

clean:
	rm -rf bpf/firewall.bpf.o bin control/__pycache__ tests/__pycache__ bench/__pycache__
