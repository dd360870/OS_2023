CONFIG_MODULE_SIG = n

TARGET_MODULE := kfetch_mod_312551165

obj-m := $(TARGET_MODULE).o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(RM) kfetch
load:
	sudo insmod $(TARGET_MODULE).ko
unload:
	sudo rmmod $(TARGET_MODULE) || true > /dev/null

kfetch:
	$(CC) -o kfetch kfetch.c

# test output
test: all kfetch
	$(MAKE) unload
	$(MAKE) load
	sudo ./kfetch -a
	sudo ./kfetch -c
	sudo ./kfetch
	$(MAKE) unload
