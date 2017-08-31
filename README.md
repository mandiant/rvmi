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

NOTE: rVMI will only run on Intel CPUs with virtualization extentions.  Additionally,
do not try to run rVMI within a virtualized environment.  As rVMI depends on hardware
virtualization, it will not run in an already virtualized environment.

## Installation

rVMI consists of three components, KVM kernel modules, QEMU, and Rekall. This
repository will pull in all required components and install them with one
simple install script.

For those that are interested, the repositories for these components can be
found here:  
https://github.com/fireeye/rvmi-kvm  
https://github.com/fireeye/rvmi-qemu  
https://github.com/fireeye/rvmi-rekall

### Getting Started

Begin by cloning the rVMI repository:

```
$ git clone --recursive https://github.com/fireeye/rvmi.git
$ cd rvmi
```

### Build

Building all components is handled by the install script. Simply perform the
following steps:

```
$ ./install.sh build
```

### Install

The install script can also handle the installation of all components. This
will install the following components:
* qmp python module
* rVMI QEMU
* rVMI Rekall
* rVMI KVM modules

Installing these components can be achieved with the following command:

```
$ ./install.sh install
```

#### Kernel Module Persistence
This will not install the kernel modules in a persistent manner (it will not
survive a reboot). In order to make these changes persistent, you must replace
your KVM modules on the disk. Once built, the kernel modules can be found here:  
kvm-rvmi-kmod/x86/*.ko

These modules must be copied to the proper location on your machine.  This can
be found by running:
```
$ modinfo kvm
```

Copy the kernel modules to the location specified by the "filename" output of
the above command.

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
