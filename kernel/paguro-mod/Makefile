# Out-of-tree Rust-for-Linux module. Needs a kernel built with CONFIG_RUST=y
# and its build tree (make LLVM=1 rustavailable must succeed).
KDIR ?= /lib/modules/$(shell uname -r)/build

default:
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=1 clean
