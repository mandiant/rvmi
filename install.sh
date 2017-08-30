#!/bin/bash

if [ "${1}" = "build" ]; then
    echo "build rVMI"

    cd rvmi-qemu
    ./configure --target-list=x86_64-softmmu
    make
    cd ../

    cd kvm-rvmi-kmod
    ./configure
    make sync
    make
    cd ../

elif [ "${1}" = "install" ]; then
    echo "install rVMI"

    cd python/qmp/
    python ./setup.py install
    cd ../../

    cd rvmi-qemu
    make install
    cd ../

    cd rvmi-rekall/rekall-core
    python ./setup.py install
    cd ../rekall-agent
    python ./setup.py install
    cd ../
    python ./setup.py install
    cd ../

    rmmod kvm-intel
    rmmod kvm
    insmod kvm-rvmi-kmod/x86/kvm.ko
    insmod kvm-rvmi-kmod/x86/kvm-intel.ko
else
    echo "Usage: ${0} [build | install]"
fi
