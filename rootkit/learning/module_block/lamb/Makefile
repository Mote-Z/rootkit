obj-m   := lkm.o
 
KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
 
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	${MAKE} clean \
                --directory "/lib/modules/$(shell uname --release)/build" \
M="$(shell pwd)"
