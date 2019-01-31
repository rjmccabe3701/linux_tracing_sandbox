# MESSING WITH NFTABLES

I'm sitting in lab 56 with a number of windows machines that need network
access.  There is a Linux machine running a 4.19.x kernel connected to CCANET
(via a firewalled "lab" nic: eno1).  This machine's name is wazowski and has a
secondary nic (eno2) connected to a switch,  this switch is also connected to
the Linux machines of interests.

I'm on one of the windows machines (192.168.4.110/24), just trying to ping out
to ng.rockwellcollins.lab (10.53.134.11).  I set eno2's IP to 192.168.4.1/24.

I started from this:

https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)

and noticed that iptables and nftables don't play nice.

This site

https://blog.printk.io/2018/06/iptable-prevents-nftables-to-be-loaded/

says to do this:

```bash
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
rmmod iptable_nat
```

I started out by creating a snat.cfg file:


```
table ip nat {
   chain prerouting {
      type nat hook prerouting priority 0; policy accept;
   }

   chain postrouting {
      type nat hook postrouting priority 100; policy accept;
      oifname eno1 counter masquerade;
   }
}
```

And added this config via

```bash
nft -f ./snat.cfg
```

I then started experimenting the BCC's "trace" tool (I wanted to see how nft interacts with the kernel):

Adding a table:

```
sudo ./trace -a -K -I linux/netlink.h -I /usr/src/linux-headers-4.19.18-041918/include/net/net_namespace.h \
'nf_tables_newtable(struct net *net, struct sock *nlsk, struct sk_buff *skb, const struct nlmsghdr *nlh, const struct nlattr ** const nla, struct netlink_ext_ack *extack) "test = %lld, len = %u, type = %u, table_name = %s", net->ifindex, (int)nla[1]->nla_len, nla[1]->nla_type, ((long int)nla[1])+4' \
'r::nf_tables_newtable "ret = %d", retval' 'r::__x64_sys_sendmsg "ret = %d", retval' 'nft_masq_init'

PID     TID     COMM            FUNC             -
6999    6999    nft             __x64_sys_sendmsg ret = 60
      ffffffffac46b6f0 kretprobe_trampoline+0x0 [kernel]
      ffffffffad000088 entry_SYSCALL_64_after_hwframe+0x44 [kernel]

7000    7000    nft             nft_masq_init
      ffffffffc0807001 nft_masq_init+0x1 [kernel]
      ffffffffc056fada nfnetlink_rcv_batch+0x46a [kernel]
      ffffffffc056fd98 nfnetlink_rcv+0x118 [kernel]
      ffffffffaccf3bd4 netlink_unicast+0x1a4 [kernel]
      ffffffffaccf3e9d netlink_sendmsg+0x20d [kernel]
      ffffffffacc84f2e sock_sendmsg+0x3e [kernel]
      ffffffffacc85535 ___sys_sendmsg+0x295 [kernel]
      ffffffffacc8762c __sys_sendmsg+0x5c [kernel]
      ffffffffacc8768f __x64_sys_sendmsg+0x1f [kernel]
      ffffffffac46b6f0 kretprobe_trampoline+0x0 [kernel]
      ffffffffad000088 entry_SYSCALL_64_after_hwframe+0x44 [kernel]

7000    7000    nft             nf_tables_newtable ret = 0
      ffffffffac46b6f0 kretprobe_trampoline+0x0 [kernel]
      ffffffffc056fd98 nfnetlink_rcv+0x118 [kernel]
      ffffffffaccf3bd4 netlink_unicast+0x1a4 [kernel]
      ffffffffaccf3e9d netlink_sendmsg+0x20d [kernel]
      ffffffffacc84f2e sock_sendmsg+0x3e [kernel]
      ffffffffacc85535 ___sys_sendmsg+0x295 [kernel]
      ffffffffacc8762c __sys_sendmsg+0x5c [kernel]
      ffffffffacc8768f __x64_sys_sendmsg+0x1f [kernel]
      ffffffffac46b6f0 kretprobe_trampoline+0x0 [kernel]
      ffffffffad000088 entry_SYSCALL_64_after_hwframe+0x44 [kernel]

7000    7000    nft             nf_tables_newtable test = 4, len = 8, type = 1, table_name = nat
      ffffffffc0652eb1 nf_tables_newtable+0x1 [kernel]
      ffffffffc056fd98 nfnetlink_rcv+0x118 [kernel]
      ffffffffaccf3bd4 netlink_unicast+0x1a4 [kernel]
      ffffffffaccf3e9d netlink_sendmsg+0x20d [kernel]
      ffffffffacc84f2e sock_sendmsg+0x3e [kernel]
      ffffffffacc85535 ___sys_sendmsg+0x295 [kernel]
      ffffffffacc8762c __sys_sendmsg+0x5c [kernel]
      ffffffffacc8768f __x64_sys_sendmsg+0x1f [kernel]
      ffffffffac46b6f0 kretprobe_trampoline+0x0 [kernel]
      ffffffffad000088 entry_SYSCALL_64_after_hwframe+0x44 [kernel]

7000    7000    nft             __x64_sys_sendmsg ret = 396
      ffffffffac46b6f0 kretprobe_trampoline+0x0 [kernel]
      ffffffffad000088 entry_SYSCALL_64_after_hwframe+0x44 [kernel]
```


Listing the rules (in another term do "nft list ruleset"):

```
sudo ./trace -a -K -I linux/netlink.h -I /usr/src/linux-headers-4.19.18-041918/include/net/net_namespace.h 'nft_masq_dump'

PID     TID     COMM            FUNC
7092    7092    nft             nft_masq_dump
      ffffffffc08070a1 nft_masq_dump+0x1 [kernel]
      ffffffffc065a1b6 nf_tables_fill_rule_info.isra.63+0x1e6 [kernel]
      ffffffffc065a77d nf_tables_dump_rules+0x1cd [kernel]
      ffffffffaccf0feb netlink_dump+0x12b [kernel]
      ffffffffaccf1ee3 __netlink_dump_start+0x163 [kernel]
      ffffffffc0651454 nft_netlink_dump_start_rcu.constprop.74+0x44 [kernel]
      ffffffffc065a552 nf_tables_getrule+0x1f2 [kernel]
      ffffffffc056f2f0 nfnetlink_rcv_msg+0x160 [kernel]
      ffffffffaccf43a2 netlink_rcv_skb+0x52 [kernel]
      ffffffffc056fcef nfnetlink_rcv+0x6f [kernel]
      ffffffffaccf3bd4 netlink_unicast+0x1a4 [kernel]
      ffffffffaccf3e9d netlink_sendmsg+0x20d [kernel]
      ffffffffacc84f2e sock_sendmsg+0x3e [kernel]
      ffffffffacc87124 __sys_sendto+0x114 [kernel]
      ffffffffacc871d8 __x64_sys_sendto+0x28 [kernel]
      ffffffffac40427a do_syscall_64+0x5a [kernel]
      ffffffffad000088 entry_SYSCALL_64_after_hwframe+0x44 [kernel]
```

I next played a bit with the nft tool, itself:

```
root@wazowski:~# nft list ruleset
table ip nat {
      chain prerouting {
            type nat hook prerouting priority 0; policy accept;
      }
}
root@wazowski:~# nft  -f ./snat.cfg
root@wazowski:~# nft list ruleset
table ip nat {
      chain prerouting {
            type nat hook prerouting priority 0; policy accept;
      }

      chain postrouting {
            type nat hook postrouting priority 100; policy accept;
            oifname "poopy" masquerade
      }
}
root@wazowski:~# nft delete rule nat postrouting oifname "poopy" masquerade
Error: syntax error, unexpected oifname, expecting handle
delete rule nat postrouting oifname poopy masquerade
                     ^^^^^^^
root@wazowski:~# nft delete rule nat postrouti^C oifname "poopy" masquerade
root@wazowski:~# nft -a list ruleset
table ip nat {
      chain prerouting {
            type nat hook prerouting priority 0; policy accept;
      }

      chain postrouting {
            type nat hook postrouting priority 100; policy accept;
            oifname "poopy" masquerade # handle 5
      }
}
root@wazowski:~# nft delete rule nat postrouting handle 5
root@wazowski:~# nft -a list ruleset
table ip nat {
      chain prerouting {
            type nat hook prerouting priority 0; policy accept;
      }

      chain postrouting {
            type nat hook postrouting priority 100; policy accept;
      }
}

table ip nat {
      chain prerouting {
            type nat hook prerouting priority 0; policy accept;
      }

      chain postrouting {
            type nat hook postrouting priority 100; policy accept;
            oifname "eno2" masquerade # handle 3
            nftrace set 1 accept # handle 5
      }
}
```


Still no reachability from 192.168.4.110, so I started tracking the IP stack:

Print transport protocol:

```bash
sudo ./trace -a -K -I linux/skbuff.h -I linux/ip.h \
   'ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) "proto = %d", (int)((struct iphdr*)skb_network_header(skb))->protocol'
```

I discovered you cant do this because eBPF requires strict boundaries when looking thru pkt memory.  So I found the common values of the "skb->network_header"
(which is the offest to the iphdr from the skb->head):

```bash
#Find weird network_header offsets (found 16)
sudo ./trace -v -a -K -I linux/skbuff.h -I linux/ip.h \
   'ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) (skb->network_header != 264 && skb->network_header != 252) "unknown header offset = %d", skb->network_header'


#print network headers
sudo ./trace -v -a -K -I linux/skbuff.h -I linux/ip.h \
   'ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) (skb->network_header == 264) "proto = %d", ((struct iphdr*)(skb->head + 264))->protocol' \
   'ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) (skb->network_header == 252) "proto = %d", ((struct iphdr*)(skb->head + 252))->protocol'

#only print ICMP
#From this i learned the windows machine's ICMP pkts weren't making it to ip_output
sudo ./trace -v -a -K -I linux/skbuff.h -I linux/ip.h \
   'ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) (skb->network_header == 264 && ((struct iphdr*)(skb->head + 264))->protocol == 1) "HERE 264"' \
   'ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) (skb->network_header == 252 && ((struct iphdr*)(skb->head + 252))->protocol == 1) "HERE 252"' \
   'ip_output(struct net *net, struct sock *sk, struct sk_buff *skb) (skb->network_header == 16 && ((struct iphdr*)(skb->head + 16))->protocol == 1) "HERE 16"'
```

At this point I started pinging pinging wazowski from the windows machine and I see:

```
   0       0       swapper/9       ip_output        HERE 16
        ffffffffacd05fd1 ip_output+0x1 [kernel]
        ffffffffacd06979 ip_send_skb+0x19 [kernel]
        ffffffffacd069d3 ip_push_pending_frames+0x33 [kernel]
        ffffffffacd3ba9f icmp_push_reply+0xdf [kernel]
        ffffffffacd3cdd0 icmp_reply.constprop.34+0x2a0 [kernel]
        ffffffffacd3ce3d icmp_echo.part.26+0x5d [kernel]
        ffffffffacd3ce90 icmp_echo+0x30 [kernel]
        ffffffffacd3d11d icmp_rcv+0x16d [kernel]
        ffffffffaccffca2 ip_local_deliver_finish+0x62 [kernel]
        ffffffffacd002ef ip_local_deliver+0x6f [kernel]
        ffffffffacd00125 ip_rcv_finish+0x55 [kernel]
        ffffffffacd003b6 ip_rcv+0x56 [kernel]
        ffffffffacca9c07 __netif_receive_skb_one_core+0x57 [kernel]
        ffffffffacca9c68 __netif_receive_skb+0x18 [kernel]
```

And this gives me an idea:  Why not trace ``ip_rcv`` all and inspect all pkts coming from eno2 (interface to 192.168.4.110)


```bash
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
     'ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) "iif = %s", orig_dev->name'
```

yields:

```
TIME     PID     TID     COMM            FUNC             -
17:19:01 0       0       swapper/36      ip_rcv           iif = eno1
17:19:01 0       0       swapper/36      ip_rcv           iif = eno1
17:19:01 0       0       swapper/36      ip_rcv           iif = eno1
17:19:01 0       0       swapper/36      ip_rcv           iif = eno1
17:19:01 0       0       swapper/44      ip_rcv           iif = eno1
17:19:01 0       0       swapper/36      ip_rcv           iif = eno1
```


Now to strcmp that interface name:

```
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
     'ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) (STRCMP("eno2", orig_dev->name)) "iif = %s", orig_dev->name'

TIME     PID     TID     COMM            FUNC             -
17:23:57 0       0       swapper/28      ip_rcv           iif = eno2
17:23:57 0       0       swapper/18      ip_rcv           iif = eno2
17:24:00 0       0       swapper/28      ip_rcv           iif = eno2
```

Ok I'm in business, find the ``iphdr`` offset at this point in the kernel:

```bash
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
     'ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) (STRCMP("eno2", orig_dev->name)) "iif = %s, skb->network_header = %d ", orig_dev->name, (int)skb->network_header'
```

From this I learned the ``network_header`` offset is 78.

```
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
     'ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) (STRCMP("eno2", orig_dev->name)) "iif = %s, ipproto = %d ", orig_dev->name, ((struct iphdr*)(skb->head + 78))->protocol'

TIME     PID     TID     COMM            FUNC             -
17:27:11 0       0       swapper/9       ip_rcv           iif = eno2, ipproto = 1
17:27:13 0       0       swapper/9       ip_rcv           iif = eno2, ipproto = 1
17:27:13 0       0       swapper/28      ip_rcv           iif = eno2, ipproto = 17
17:27:13 0       0       swapper/18      ip_rcv           iif = eno2, ipproto = 17
17:27:14 0       0       swapper/9       ip_rcv           iif = eno2, ipproto = 1
17:27:16 0       0       swapper/9       ip_rcv           iif = eno2, ipproto = 1
17:27:17 0       0       swapper/9       ip_rcv           iif = eno2, ipproto = 1
17:27:19 0       0       swapper/9       ip_rcv           iif = eno2, ipproto = 1

```

Looks like the windows machine is sending ICMP (I'm pinging) and UDP (probably DNS).  Hmmmm, lets see what ``ip_rcv`` is returning:

```c
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
      struct net_device *orig_dev)
{
   struct net *net = dev_net(dev);

   skb = ip_rcv_core(skb, net);
   if (skb == NULL)
      return NET_RX_DROP;
   return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
         net, NULL, skb, dev, NULL,
         ip_rcv_finish);
}
```


```bash
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
     'ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) (STRCMP("eno2", orig_dev->name)) "iif = %s, ipproto = %d ", orig_dev->name, ((struct iphdr*)(skb->head + 78))->protocol' \
     'r::ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) (STRCMP("eno2", orig_dev->name)) "RET = %d", retval'
```

Hmmmm, no retval .... Maybe you can't filter on a return trace?  Printing them all:


```
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
    'ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) (STRCMP("eno2", orig_dev->name)) "iif = %s, ipproto = %d ", orig_dev->name, ((struct iphdr*)(skb->head + 78))->protocol' \
     'r::ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) "RET = %d, iif = %s", retval, orig_dev->name'

17:35:56 0       0       swapper/36      ip_rcv           RET = 0, iif =
17:35:56 0       0       swapper/36      ip_rcv           RET = 0, iif =
17:35:56 0       0       swapper/9       ip_rcv           RET = -1, iif =
17:35:56 0       0       swapper/9       ip_rcv           iif = eno2, ipproto = 1
17:35:56 0       0       swapper/36      ip_rcv           RET = 0, iif =
17:35:56 0       0       swapper/36      ip_rcv           RET = 0, iif =
17:35:56 0       0       swapper/36      ip_rcv           RET = 0, iif =
```

This is strange, it looks like ``orig_dev`` is unprintable on return context AND it looks like the enter and return traces got mixed.
In any case, it looks like the packets are being dropped here.  Lets make sure by verifying we see no ICMP pkts in ``ip_rcv_finish``

First verify the header offset is still 78 (it is):

```bash
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
     'ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb) (skb->network_header != 78) "oddball skb->network_header = %d ",(int)skb->network_header'
```


Assert that no ICMP packets (my ping from 192.168.4.110 to ng.rockwellcollins.lab), make it to ``ip_rcv_finish``:

```
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
    'ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb) (((struct iphdr*)(skb->head + 78))->protocol == 1) "Shouldnt get here with ICMP"'

 TIME     PID     TID     COMM            FUNC             -
 17:43:49 0       0       swapper/9       ip_rcv_finish    Shouldnt get here with ICMP
 17:43:50 0       0       swapper/9       ip_rcv_finish    Shouldnt get here with ICMP
 17:43:52 0       0       swapper/9       ip_rcv_finish    Shouldnt get here with ICMP
```

Uhoh, they are getting to ``ip_rcv_finish``! It must mean ``NF_HOOK`` didn't drop the packets, the ``ip_rcv_finish``, itself, did.

Let's look at the ``ip_rcv_finish_core`` method (called from ``ip_rcv_core``):

```bash
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
   'ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb) (((struct iphdr*)(skb->head + 78))->protocol == 1) "Shouldnt get here with ICMP"' \
   'r::ip_rcv_finish_core "retval = %d", (int)retval'
```

Hmmmm, getting invalid arguments when trying to trace on ``ip_rcv_finish_core``. Looks like there is some namespacing going on (its a static method)
Let's find the actual names:

```
-> % cat /proc/kallsyms| grep rcv_finish_core
0000000000000000 t ip_rcv_finish_core.isra.21
0000000000000000 t ip_rcv_finish_core.isra.21.cold.31
0000000000000000 t ip6_rcv_finish_core.isra.20
```

It wont let me attach to the second one (who knows why), so lets go with ``*.isra.21``:

```bash
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
     'ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb) (((struct iphdr*)(skb->head + 78))->protocol == 1) "Shouldnt get here with ICMP"' \
     'r::ip_rcv_finish_core.isra.21(struct net *net, struct sock *sk, struct sk_buff *skb) "proto = %d, retval = %d", (int)((struct iphdr*)(skb->head + 78))->protocol, (int)retval'
```

This show ``ip_rcv_finish_core`` returns 0

```
18:02:10 0       0       swapper/36      ip_rcv_finish_core.isra.21 proto = 0, retval = 0
18:02:10 0       0       swapper/36      ip_rcv_finish_core.isra.21 proto = 0, retval = 0
18:02:10 0       0       swapper/9       ip_rcv_finish_core.isra.21 proto = 0, retval = 0
18:02:10 0       0       swapper/9       ip_rcv_finish    Shouldnt get here with ICMP
18:02:10 0       0       swapper/36      ip_rcv_finish_core.isra.21 proto = 0, retval = 0
```

Now looking at ``ip_rcv_finish``:

```c
static int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
   int ret;

   /* if ingress device is enslaved to an L3 master device pass the
    * skb to its handler for processing
    */
   skb = l3mdev_ip_rcv(skb);
   if (!skb)
      return NET_RX_SUCCESS;

   ret = ip_rcv_finish_core(net, sk, skb);
   if (ret != NET_RX_DROP)
      ret = dst_input(skb);
   return ret;
}
```

The issue MUST be with ``dst_input``.  But I cannot trace on `dst_input` cuz its a static inline wrapper to an
indirect function call:

```c
static inline int dst_input(struct sk_buff *skb)
{
   return skb_dst(skb)->input(skb);
}
```

To figure out where this goes I did this:

```bash
TRACE=/sys/kernel/debug/tracing
# mount -t tracefs none $TRACE
echo 0 > $TRACE/tracing_on
echo > $TRACE/trace
echo function_graph > $TRACE/current_tracer
echo __dev_printk >> $TRACE/set_graph_notrace
echo "ip_rcv_finish" > ${TRACE}/set_graph_function
echo "ip_local_deliver" > ${TRACE}/set_graph_notrace
echo "ip_rcv_finish_core.isra.21" >> ${TRACE}/set_graph_notrace
#Don't show irqs
echo 0 > $TRACE/options/funcgraph-irqs
echo 0 > $TRACE/options/overwrite
echo 1 > $TRACE/tracing_on
```

Note:

* I am filtering out ``ip_local_deliver`` because -- before filtering this out -- I learned this is the function call
 for traffic to be locally delivered.

* I filtered out `ip_rcv_finish_core` because, I previously proved this is returning 0.

These are the trace results:

```
3)               |  ip_rcv_finish() {
3)   1.545 us    |    } /* ip_rcv_finish_core.isra.21 */
3) + 28.410 us   |    } /* ip_local_deliver */
3) + 32.591 us   |  }
9)               |  ip_rcv_finish() {
9)   3.704 us    |    } /* ip_rcv_finish_core.isra.21 */
9)               |    ip_forward() {
9)               |      nf_hook_slow() {
9)               |        iptable_mangle_hook [iptable_mangle]() {
9)               |          ipt_do_table [ip_tables]() {
9)   0.394 us    |            __local_bh_enable_ip();
9)   1.251 us    |          }
9)   1.989 us    |        }
9)               |        iptable_filter_hook [iptable_filter]() {
9)               |          ipt_do_table [ip_tables]() {
9)   0.377 us    |            __local_bh_enable_ip();
9)   1.348 us    |          }
9)   2.099 us    |        }
9)               |        kfree_skb() {
9)               |          skb_release_all() {
9)   0.461 us    |            skb_release_head_state();
9)               |            skb_release_data() {
9)               |              skb_free_head() {
9)   0.403 us    |                page_frag_free();
9)   1.118 us    |              }
9)   1.975 us    |            }
9)   3.544 us    |          }
9)               |          kfree_skbmem() {
9)   0.537 us    |            kmem_cache_free();
9)   1.318 us    |          }
9)   6.024 us    |        }
9) + 11.837 us   |      }
9) + 13.045 us   |    }
9) + 19.479 us   |  }
```

The first ``ip_rcv_finish`` call is for a local delivery (note the summary of the methods I filtered out).
The next is what I want.  Note that ``ip_forward_finish`` is not being called and it should if this passes:

```c
//in ip_rcv_finish()
return NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD,
      net, NULL, skb, skb->dev, rt->dst.dev,
      ip_forward_finish);
```

It looks like this ``iptable_filter_hook`` is failing for some reason.  Let's prove it!


```bash
sudo ./trace -v -T -I linux/skbuff.h -I linux/ip.h -I linux/netdevice.h \
    'iptable_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) (((struct iphdr*)(skb->head + 78))->protocol == 1) "ICMP PKT"'\
    'r::iptable_filter_hook "retval = %d", (int)retval'


18:35:09 0       0       swapper/36      iptable_filter_hook retval = 1
18:35:09 3558    3558    sshd            iptable_filter_hook retval = 1
18:35:09 3558    3558    sshd            iptable_filter_hook retval = 1
18:35:09 3558    3558    sshd            iptable_filter_hook retval = 1
18:35:09 3558    3558    sshd            iptable_filter_hook retval = 1
18:35:09 3558    3558    sshd            iptable_filter_hook retval = 1
18:35:09 0       0       swapper/9       iptable_filter_hook ICMP PKT
18:35:09 0       0       swapper/9       iptable_filter_hook retval = 0
18:35:09 3558    3558    sshd            iptable_filter_hook retval = 1
18:35:09 0       0       swapper/36      iptable_filter_hook retval = 1
```

Looks like a retval = 0, means drop (``NF_DROP``) (you can add a "-K" to the ./trace script to get kernel stacks to verify, but its really spammy).

Maybe I need to add explicit rules for accepting "forwarding" pkts in the filter chain ...

```
#nft -f /path/to/snat.cfg
table ip nat {
   chain prerouting {
     type nat hook prerouting priority 0; policy accept;
     ip protocol icmp counter jump poop-chain
     counter
   }

   #This isn't necessary ... i was just playing with adding
   # user-defined chains.
   chain poop-chain {
      counter
      accept
   }

# for all packets to WAN, after routing, replace source address with primary IP of WAN interface
   chain postrouting {
    type nat hook postrouting priority 100; policy accept;
     # nftrace set 1 accept;
     counter
     oifname eno1 counter masquerade;
   }
}

#Added this to see if it fixes crap
table ip filter {
   chain forward {
     type filter hook forward priority 0; policy accept;
     ip protocol icmp counter accept
   }
}
```

That didn't fix it.  Here is the ``function_graph`` trace again


```
9)               |  ip_rcv_finish() {
9)   3.621 us    |    } /* ip_rcv_finish_core.isra.21 */
9)               |    ip_forward() {
9)               |      nf_hook_slow() {
9)               |        iptable_mangle_hook [iptable_mangle]() {
9)               |          ipt_do_table [ip_tables]() {
9)   0.380 us    |            __local_bh_enable_ip();
9)   1.999 us    |          }
9)   2.973 us    |        }
9)               |        nft_do_chain_ipv4 [nf_tables]() {
9)               |          nft_do_chain [nf_tables]() {
9)               |            nft_counter_eval [nft_counter]() {
9)   0.367 us    |              __local_bh_enable_ip();
9)   1.238 us    |            }
9)   0.397 us    |            nft_immediate_eval [nf_tables]();
9)   3.280 us    |          }
9)   4.121 us    |        }
9)               |        iptable_filter_hook [iptable_filter]() {
9)               |          ipt_do_table [ip_tables]() {
9)   0.440 us    |            __local_bh_enable_ip();
9)   1.365 us    |          }
9)   2.169 us    |        }
9)               |        kfree_skb() {
9)               |          skb_release_all() {
9)               |            skb_release_head_state() {
9)               |              nf_conntrack_destroy() {
9)               |                destroy_conntrack [nf_conntrack]() {
9)   0.364 us    |                  __nf_ct_l4proto_find [nf_conntrack]();
9)   0.400 us    |                  nf_ct_remove_expectations [nf_conntrack]();
```


The new rule shows up (``nft_do_chain_ipv4``), and seems to pass.  I verify that nft is happy:

```
> nft -a list table ip filter
table ip filter {
      chain forward {
            type filter hook forward priority 0; policy accept;
            ip protocol icmp counter packets 12 bytes 720 accept # handle 2
      }
}
```

(Note the ICMP packets ticking up)

From the ftrace output it seems the issue it in the legacy iptable filter rules.
Indeed the FORWARD chain has a default DROP policy.

```
-> # iptables -L -t filter
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy DROP)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

This fixes it:

```
-> # iptables  -t filter --policy FORWARD ACCEPT
```


