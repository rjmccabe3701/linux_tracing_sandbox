# Kernel network and tracing playground


# INSTALL

** Clone Repos **
```bash
#iproute2
git clone https://git.kernel.org/pub/scm/network/iproute2/iproute2.git
#BCC (tracing)
git clone https://github.com/iovisor/bcc.git
#Kernel
https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git

#Fixup versions
#git -C iproute2 remote add https://github.com/rjmccabe3701/iproute2.git
git -C iproute2 checkout v4.19.0
git -C linux checkout b4.19.10

```

** Build tools (iproute2, kernel bpf and perf tools) **

```bash
make
source ./set_env
```
