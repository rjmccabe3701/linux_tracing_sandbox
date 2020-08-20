# Kernel network and tracing playground


## Clone Repos

```bash
#iproute2
git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git tools/iproute2
#BCC (tracing)
git clone https://github.com/iovisor/bcc.git tools/bcc
#Kernel
git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
#libbpf
git clone https://github.com/libbpf/libbpf.git tools/libbpf

#Fixup versions
#git -C tools/iproute2 remote add https://github.com/rjmccabe3701/iproute2.git
git -C tools/iproute2 checkout v5.4.0
git -C linux checkout v5.4
cp  /boot/config-$(uname -r) linux/.config
yes n | make -C linux oldconfig


#For some reason this version doesn't build the bpf examples
echo "subdir-y += bpf" >> linux/samples/Makefile
```

**Optional Repos**

```bash
#Issue: some firewalls block the native git: protocol ...
git clone git://git.netfilter.org/iptables tools/iptables
git clone git://git.netfilter.org/nftables tools/nftables
git clone git://git.netfilter.org/libnftnl tools/libnftnl
```


** Build tools (iproute2, kernel bpf and perf tools) **

First need these prerequisites:

```
sudo dnf install asciidoc xmlto bison  elfutils-libelf-devel openssl-devel \
    slang-devel gtk2-devel xz-devel libzstd-devel libpcap-devel numactl-devel \
    libbabeltrace-devel elfutils-devel libunwind-devel binutils-devel \
    libcap-devel python3-devel python2-devel readline-devel libmnl-devel

#This is assuming a fedora host machine, change as appropriate.

```


```bash
make
source ./set_env
```

## Building BCC

```
sudo apt install -y bison build-essential cmake flex git libedit-dev \
  libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev

INSTALL_DIR=$(pwd)/install
mkdir tools/bcc/build
pushd tools/bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
make -j
make install
cmake -DPYTHON_CMD=python3 .. -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}
pushd src/python/
make -j
make install
popd
popd

export LD_LIBRARY_PATH=${INSTALL_DIR}/lib
export PYTHONPATH=${INSTALL_DIR}/lib/python3/dist-packages
```

See [this](https://github.com/iovisor/bcc/issues/2915) if you get link errors


## Reading list

http://www.brendangregg.com/ebpf.html
https://github.com/cilium/ebpf
http://vger.kernel.org/lpc-bpf2018.html#session-3
