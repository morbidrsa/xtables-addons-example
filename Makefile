# Kernel
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR  := ${MODULES_DIR}/build

obj-m += xt_ipaddr.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;

lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;

lib%.o: lib%.c
	gcc -O2 -Wall -D_INIT=$*_init -fPIC -c -o $@ $<;

lib_clean:
	-@(rm *.o *.so || exit 0)
