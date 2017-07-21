![rVMI Logo](/resources/rvmi.png)

# rVMI

rVMI is a debugger on steroids. It leverages Virtual Machine Introspection (VMI)
and memory forensics to provide full system analysis. This means that an analyst
can inspect userspace processes, kernel drivers, and preboot environments in a
single tool.

It was specifially designed for interactive dynamic malware analysis. rVMI isolates
itself from the malware by placing its interactive debugging environment out of the
virtual machine (VM) onto the hypervisor-level. Through the use of VMI the analyst
still has full control of the VM, which allows her to pause the VM at any point in
time and to use typical debugging features such as breakpoints and watchpoints. In
addtion, rVMI provides access to the entire Rekall feature set, which enables an
analyst to inspect the kernel and its data structures with ease.

## Installation
We are currently working hard to get a properly packaged release available,
however for now you will need to compile and install the individual components
yourself. rVMI consists of three components, KVM kernel modules, QEMU, and Rekall.

### Installing rVMI-KVM
Repository: <https://github.com/fireeye/rvmi-kvm>

In order to build and install the KVM kernel modules, we have our VMI
changes on the 4.4 and 4.10 branches of the upstream KVM repository.
This will give you some flexibility in installing for these kernel versions.
For now, if you are interested in installing on a different kernel version,
you will have to rebase the VMI changes onto the appropriate upstream branch
yourself.

*WARNING*: rVMI is currently only compatible with Intel CPUs, these instructions
only consider the replacement of modules compatible with Intel CPUs.  Additionally,
these steps will replace the kvm kernel modules on your system.  While we preserve
backward compatibility with the vanilla modules, we do not guarantee that these
modules are bug free and therefore do not recommend you try this on a machine on
which you rely on KVM.

Begin by checking out the branch appropriate for your kernel version.
For this walk-through, we will be using the linux-4.4.y-vmi branch.

```
$ git clone https://github.com/fireeye/rvmi-kvm.git rvmi-kvm
$ cd rvmi-kvm
$ git checkout linux-4.4.y-vmi
```

At this point you will have to copy your current kernel config into this folder.
Generally, the config can be found in the /boot/ directory.  The name and location
of this config may vary depending on your Linux distribution.

```
$ cp /boot/config-`uname -r` .config
$ cp /usr/src/linux-headers-$(uname -r)/Module.symvers .
```

Having done this, you will need to configure your kernel.

```
$ yes "" | make oldconfig
$ make prepare
$ make scripts
```

Once the kernel is built, subsequent compilation of the kvm modules can be completed
with:

```
$ make modules SUBDIR=arch/x86/kvm/
```

The generated modules will replace your current KVM modules.  In order to replace
them temporarily, follow these steps:

```
$ sudo rmmod kvm-intel
$ sudo rmmod kvm
$ sudo insmod arch/x86/kvm/kvm.ko
$ sudo insmod arch/x86/kvm/kvm-intel.ko
```

If you would like to replace them permanently, please follow these steps (we
recommend you first try replacing the modules temporarily to make sure they work):

```
$ sudo cp arch/x86/kvm/kvm.ko /lib/modules/$(uname -r)/kernel/arch/x86/kvm/kvm.ko
$ sudo cp arch/x86/kvm/kvm-intel.ko /lib/modules/$(uname -r)/kernel/arch/x86/kvm/kvm-intel.ko
$ sudo modprobe -r kvm-intel
$ sudo modprobe -r kvm
$ sudo modprobe kvm
$ sudo modprobe kvm-intel
```

### Installing rVMI-QEMU
Repository: <https://github.com/fireeye/rvmi-qemu>

We recommend that you remove any previously installed versions of QEMU you
may have installed.

Begin by cloning the repository.

```
$ git clone https://github.com/fireeye/rvmi-qemu.git rvmi-qemu
```

Then, simply configure, compile, and install.

```
$ cd rvmi-qemu
$ ./configure --target-list=x86_64-softmmu
$ make
$ sudo make install
```

### Installing rVMI-Rekall
Repository: <https://github.com/fireeye/rvmi-rekall>

We recommend that you remove any previously installed versions of Rekall you may
have installed.

```
$ git clone https://github.com/fireeye/rvmi-rekall.git rvmi-rekall
```

Then install rekall.  We found that we had some issues when simply installing
from the top level, so we recommend installing the rekall-agent and rekall-core
components explicitly first.

```
$ cd rvmi-rekall/rekall-core
$ sudo python ./setup.py install
$ cd ../rekall-agent
$ sudo python ./setup.py install
$ cd ..
$ sudo python ./setup.py install
```

## Using rVMI

### Start the VM
The first step in starting rVMI is to start a VM.  We will not cover creating a VM
as the steps are the same as creating a VM for QEMU and these instructions are
readily available online.  We do recommend that you use a qcow2 image as this will
support snapshots within the image format.

You may start qemu in the standard way, paying attention that you enable KVM and QMP:

```
$ qemu-system-x86_64 -enable-kvm -qmp unix:[QMP SOCK PATH],server,nowait [...]
```

We have also included a python wrapper script that automatically incorporates these
options. You can access the help for this script using the -h flag.

```
$ qemu.py -h
```

Important is that you have the qmp socket path to pass to rekall in the next step.

### Start Rekall

Use the qmp socket path to start rekall.

```
$ rekall -f [QMP SOCK PATH]
```

## Licensing and Copyright

Copyright 2017 FireEye, Inc. All Rights Reserved.

All Rights Reserved

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation. Version 2
of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.

## Bugs and Support

There is no support provided. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.

If you think you've found a bug and you are not sure to which subproject
(rVMI-KVM, rVMI-QEMU, rVMI-Rekall) it belongs or if you want to file a
general bug, please report here:

https://github.com/fireeye/rvmi/issues

Otherwise please report the bug in the repository of the subproject
where the bug is located in:.

https://github.com/fireeye/rvmi-qemu/issues  
https://github.com/fireeye/rvmi-kvm/issues  
https://github.com/fireeye/rvmi-rekall/issues

For more details on the bug submission process, take a look at the
README file of the subproject.
