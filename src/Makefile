KERNEL_VER = `uname -r`

EXTRA_CFLAGS += -Wall -Werror $(INCLUDE_DIRS)

ifdef KBFD_REFCNT_DEBUG
	EXTRA_CFLAGS += -D KBFD_REFCNT_DEBUG
endif
ifdef DEBUG
	EXTRA_CFLAGS += -D CTRL_DEBUG -D ECHO_DEBUG
endif
ifdef CTRL_DEBUG
	EXTRA_CFLAGS += -D CTRL_DEBUG
endif
ifdef ECHO_DEBUG
	EXTRA_CFLAGS += -D ECHO_DEBUG
endif

TARGET=kbfd

obj-m += $(TARGET).o

$(TARGET)-objs := \
	kbfd_session.o \
	kbfd_packet.o \
	kbfd_main.o \
	kbfd_interface.o \
	kbfd_log.o \
	kbfd_netlink.o \
	kbfd_v4v6.o \
	kbfd_feature.o \

$(TARGET).objs :=  \
	kbfd_session_proc.o \
	kbfd_packet_proc.o \
	kbfd_main_proc.o \
	kbfd_log_proc.o \
	kbfd_v4v6_proc.o \
	kbfd_netlink_proc.o \
	kbfd_interface_proc.o \
	kbfd_feature_proc.o \
	proc_compat_proc.o

all: sources = Makefile kbfd_session.[ch] kbfd_packet.[ch] kbfd_main.c \
	kbfd_log.[ch] kbfd_v4v6.[ch] kbfd_netlink.[ch] kbfd_interface.[ch] \
	kbfd_feature.[ch] kbfd.h proc_compat.h
all: make_modules = make -C /lib/modules/$(KERNEL_VER)/build modules M=$(shell pwd)
all: make_process = make $(TARGET).proc
all:
	$(call make_modules)
	$(call make_process)

$(TARGET).proc: $($(TARGET).objs)
	$(CC) -o $@ $^ -lpthread -lrt

%_proc.o: %.c proc_compat.h
	$(CC) -D_GNU_SOURCE $(EXTRA_CFLAGS) -g -c $< -o $@ 


clean:
	-rm -f ${TARGET}.o ${TARGET}.ko 
	-rm -f ${TARGET}.proc
	-rm -f *.o

install: make_modules_install = make -C /lib/modules/$(KERNEL_VER)/build modules_install M=$(shell pwd) INSTALL_MOD_PATH=$(DESTDIR) INSTALL_MOD_DIR=kernel/drivers/net
install:
	$(call make_modules_install)
	install -D -m444 kbfd_netlink.h $(DESTDIR)/usr/include/kbfd/kbfd_netlink.h	
	install -D -m755 kbfd.proc $(DESTDIR)/usr/bin/kbfd.proc

check:
dist:

