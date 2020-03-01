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


Makefile.config:360: No libelf found. Disables 'probe' tool, jvmti and BPF support in 'perf record'. Please install libelf-dev, libelf-devel or elfutils-libelf-devel
Makefile.config:572: Disabling post unwind, no support found.
Makefile.config:637: No libcrypto.h found, disables jitted code injection, please install openssl-devel or libssl-dev
Makefile.config:653: slang not found, disables TUI support. Please install slang-devel, libslang-dev or libslang2-dev
Makefile.config:670: GTK2 not found, disables GTK2 support. Please install gtk2-devel or libgtk2.0-dev
Makefile.config:813: No liblzma found, disables xz kernel module decompression, please install xz-devel/liblzma-dev
Makefile.config:826: No libzstd found, disables trace compression, please install libzstd-dev[el] and/or set LIBZSTD_DIR
Makefile.config:837: No libcap found, disables capability support, please install libcap-devel/libcap-dev
Makefile.config:850: No numa.h found, disables 'perf bench numa mem' benchmark, please install numactl-devel/libnuma-devel/libnuma-dev
Makefile.config:905: No libbabeltrace found, disables 'perf data' CTF format support, please install libbabeltrace-dev[el]/libbabeltrace-ctf-dev
