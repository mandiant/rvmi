$(if $(wildcard config.mak),,$(error Please run configure first))
include config.mak

ARCH_DIR = $(if $(filter $(ARCH),x86_64 i386),x86,$(ARCH))
ARCH_CONFIG := $(shell echo $(ARCH_DIR) | tr '[:lower:]' '[:upper:]')
# NONARCH_CONFIG used for unifdef, and only cover X86 now
NONARCH_CONFIG = $(filter-out $(ARCH_CONFIG),X86)

DESTDIR = /

MAKEFILE_PRE = $(ARCH_DIR)/Makefile.pre

export INSTALL_MOD_DIR=updates

rpmrelease = devel

LINUX = ./linux

all:: prerequisite
#	include header priority 1) $LINUX 2) $KERNELDIR 3) include-compat
	$(MAKE) -C $(KERNELDIR) M=`pwd` \
		LINUXINCLUDE="-I`pwd`/include -I`pwd`/include/uapi -Iinclude \
			$(if $(KERNELSOURCEDIR),\
				-Iinclude2 -I$(KERNELSOURCEDIR)/include \
				-I$(KERNELSOURCEDIR)/include/uapi \
				-I$(KERNELSOURCEDIR)/arch/${ARCH_DIR}/include \
				-I$(KERNELSOURCEDIR)/arch/${ARCH_DIR}/include/uapi, \
				-Iinclude/uapi -Iarch/${ARCH_DIR}/include \
				-Iarch/${ARCH_DIR}/include/uapi) \
			-Iinclude/generated/uapi -Iarch/${ARCH_DIR}/include/generated \
			-Iarch/${ARCH_DIR}/include/generated/uapi \
			-I`pwd`/include-compat -I`pwd`/${ARCH_DIR} \
			-include $(if $(wildcard $(KERNELDIR)/include/generated), \
				include/generated/autoconf.h, \
				include/linux/autoconf.h) \
			-include `pwd`/$(ARCH_DIR)/external-module-compat.h" \
		"$$@"

include $(MAKEFILE_PRE)

KVM_VERSION_GIT = $(if $(and $(filter kvm-devel,$(KVM_VERSION)), \
			 $(wildcard $(LINUX)/.git)), \
			   $(shell git --git-dir=$(LINUX)/.git describe), \
			   $(KVM_VERSION))

sync:
	./sync -v $(KVM_VERSION_GIT) -l $(LINUX)

KVM_KMOD_VERSION = $(strip $(if $(wildcard KVM_VERSION), \
			$(shell cat KVM_VERSION), \
			$(if $(wildcard .git), \
				$(shell git describe), \
				kvm-devel)))

modules_install:
	$(MAKE) -C $(KERNELDIR) M=`pwd` INSTALL_MOD_PATH=$(DESTDIR)/$(INSTALL_MOD_PATH) $@

install: modules_install
	install -m 644 -D scripts/65-kvm.rules $(DESTDIR)/etc/udev/rules.d/65-kvm.rules

tmpspec = .tmp.kvm-kmod.spec

rpm-topdir := $$(pwd)/rpmtop

RPMDIR = $(rpm-topdir)/RPMS

rpm:	all
	mkdir -p $(rpm-topdir)/BUILD $(RPMDIR)/$$(uname -i)
	sed 's/^Release:.*/Release: $(rpmrelease)/; s/^%define kverrel.*/%define kverrel $(KERNELVERSION)/' \
	     kvm-kmod.spec > $(tmpspec)
	rpmbuild --define="kverrel $(KERNELVERSION)" \
		 --define="objdir $$(pwd)/$(ARCH_DIR)" \
		 --define="_rpmdir $(RPMDIR)" \
		 --define="_topdir $(rpm-topdir)" \
		-bb $(tmpspec)

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@

distclean: clean
	rm -f config.mak kvm-kmod-config.h include/asm include-compat/asm $(tmpspec)

.PHONY: all sync install rpm clean distclean
