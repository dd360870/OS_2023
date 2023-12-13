CONFIG_MODULE_SIG = n
TARGET_MODULE := kfetch_mod_312551165

obj-m := $(TARGET_MODULE).o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: kfetch
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) kfetch out
load:
	sudo insmod $(TARGET_MODULE).ko
unload:
	sudo rmmod $(TARGET_MODULE) || true >/dev/null

kfetch: kfetch.c
	$(CC) -o $@ $^

test: all
	$(MAKE) unload
	$(MAKE) load
	sudo ./kfetch -a > out 2>&1
	$(MAKE) unload
	cat out
