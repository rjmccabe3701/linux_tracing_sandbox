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
git -C tools/iproute2 checkout v5.3.0
git -C linux checkout v5.3
cp  /boot/config-$(uname -r) linux/.config

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



To build bcc do this:

```
sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev
cd tools/bcc
mkdir build; cd build
cmake ../ -DCMAKE_INSTALL_PREFIX=$(pwd)/../../../install
make -j
make install
```


## Reading list

http://www.brendangregg.com/ebpf.html
