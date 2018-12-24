# Kernel network and tracing playground


## Clone Repos

```bash
#iproute2
git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git tools/iproute2
#BCC (tracing)
git clone https://github.com/iovisor/bcc.git tools/bcc
#Kernel
https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

#Fixup versions
#git -C tools/iproute2 remote add https://github.com/rjmccabe3701/iproute2.git
git -C tools/iproute2 checkout v4.19.0
git -C linux checkout b4.19.10

```

**Optional Repos**

```bash
git clone git://git.netfilter.org/iptables tools/iptables
git clone git://git.netfilter.org/nftables tools/nftables
git clone git://git.netfilter.org/libnftnl tools/libnftnl
```


** Build tools (iproute2, kernel bpf and perf tools) **

```bash
make
source ./set_env
```
