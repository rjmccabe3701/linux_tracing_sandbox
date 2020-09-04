#Playing with Cilium


## Installing Cilium on microk8s

See:
https://github.com/ubuntu/microk8s/blob/master/microk8s-resources/actions/enable.cilium.sh

```bash
#Need to run without http proxy vars otherwise, the dns service gets mad
http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= snap run microk8s.start

#Enable dns (used to resolve service to cluster ips, e.g: deathstar.default.svc.cluster.local)
sudo /snap/bin/microk8s.enable dns

#Might need to change the default DNS servers:
microk8s kubectl -n kube-system edit configmap/coredns

#Enable cilium (can change cilium version with the ":" arg)
sudo /snap/bin/microk8s.enable cilium:v1.8
```

Running the cilium cmd line tool outside a continer:

```bash
alias cilium='CILIUM_HEALTH_SOCK=/var/snap/microk8s/current/var/run/cilium/health.sock \
CILIUM_MONITOR_SOCK=/var/snap/microk8s/current/var/run/cilium/monitor1_2.sock \
CILIUM_SOCK=/var/snap/microk8s/current/var/run/cilium/cilium.sock \
   ~/go/src/github.com/cilium/cilium/examples/getting-started/cilium'

cilium status
```

----

Trying to figure out how cilium attached ebpf programs:

```
   sudo bpftool net list
   xdp:

   tc:
   eno1np0(3) clsact/ingress bpf_netdev_eno1np0.o:[from-netdev] id 12098
   eno1np0(3) clsact/egress bpf_netdev_eno1np0.o:[to-netdev] id 12104
   cilium_net(913) clsact/ingress bpf_host_cilium_net.o:[to-host] id 12092
   cilium_host(914) clsact/ingress bpf_host.o:[to-host] id 12080
   cilium_host(914) clsact/egress bpf_host.o:[from-host] id 12086
   cilium_vxlan(930) clsact/ingress bpf_overlay.o:[from-overlay] id 12050
   cilium_vxlan(930) clsact/egress bpf_overlay.o:[to-overlay] id 12055
   lxc_health(954) clsact/ingress bpf_lxc.o:[from-container] id 12068
   lxcf221c8fd6baa(956) clsact/ingress bpf_lxc.o:[from-container] id 12110
   lxcbe9057961e74(958) clsact/ingress bpf_lxc.o:[from-container] id 12116
   lxc9e21f2e97a0b(960) clsact/ingress bpf_lxc.o:[from-container] id 12140
   lxc82cff8197450(962) clsact/ingress bpf_lxc.o:[from-container] id 12142
   lxca5c9a6d90e69(964) clsact/ingress bpf_lxc.o:[from-container] id 12122

   flow_dissector:
```
   

Looks like it puts them on ingress/egress qdiscs

```
   sudo tc filter show dev lxcf221c8fd6baa ingress
   filter protocol all pref 1 bpf chain 0
   filter protocol all pref 1 bpf chain 0 handle 0x1 bpf_lxc.o:[from-container] direct-action not_in_hw id 12110
   tag ae4beb8ed518b348 jited
```

These interfaces are veths (not sure where their other end lives)

```
    cilium debuginfo | grep state-dir

    state-dir:/var/run/cilium
```

In the cilium-agent container:

```
 root@gauss:/var/run/cilium/state# find . -name '*.o'
 ./bpf_overlay.o
 ./4000/bpf_lxc.o
 ./4000/template.o
 ./bpf_sock.o
 ./2431/bpf_lxc.o
 ./2431/template.o
 ./2950/bpf_lxc.o
 ./2950/template.o
 ./1037/bpf_lxc.o
 ./1037/template.o
 ./bpf_alignchecker.o
 ./1446/bpf_lxc.o
 ./1446/template.o
 ./2038/bpf_lxc.o
 ./2038/template.o
 ./135/bpf_host_cilium_net.o
 ./135/bpf_host.o
 ./135/template.o
 ./135/bpf_netdev_eno1np0.o
 ./templates/6c1097c4abca946a16b9386fe6b50633cd71342d/bpf_lxc.o
 ./templates/5401ce0a2b3a7c5b0c29e8e2c3c4664d555b57ad/bpf_host.o
```

Looks like cilium compiles these templates:
https://github.com/cilium/cilium/blob/master/bpf/bpf_lxc.c


From the docs:
   When implementing ClusterIP, Cilium acts on the same principles as kube-proxy, it watches for services
   addition or removal, but instead of doing the enforcement on the iptables, it updates BPF map entries on
   each node.

----

CNI stuff

Looks like k8s used the CNI protocol to talk to cilium's CNI plugin:

```
   -> % cat /var/snap/microk8s/1609/args/cni-network/05-cilium-cni.conf
   {
      "cniVersion": "0.3.1",
      "name": "cilium",
      "type": "cilium-cni",
      "enable-debug": true
   }

   -> % /var/snap/microk8s/1609/opt/cni/bin/cilium-cni
   Cilium CNI plugin 1.8.2 aa42034f0 2020-07-23T15:02:39-07:00 go version go1.14.6 linux/amd64
```

Cilium's [cni-plugin](https://github.com/cilium/cilium/blob/master/plugins/cilium-cni/cilium-cni.go) sets
itself up to react to JSON-formatted stdin commands from k8s:


```go
func main() {
	skel.PluginMain(cmdAdd,
		nil,
		cmdDel,
		cniVersion.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1"),
		"Cilium CNI plugin "+version.Version)
}
```

In the ``cmdAdd`` method it does:

``c, err = client.NewDefaultClientWithTimeout(defaults.ClientConnectTimeout)`` which opens up a unix domain
socket to the cilium agent (running in the cilium daemon set).

Looks like ``cmdAdd`` will directly create interfaces, but calls into the cilium client to notify it about
endpoints.

What I don't yet understand: how the cilium-cni interacts with cilium's k8s operator.  And why the need for
both?

----

Nifty way to run apply a kubectl file on the command line:

```
-> % kk apply -f <(
cat << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  selector:
    matchLabels:
      app: nginx
  replicas: 2
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx
        resources:
          limits:
            memory: "128Mi"
            cpu: "500m"
        ports:
        - containerPort: 80
EOF
)
deployment.apps/nginx-deployment created
```



--- helm

Looks like the microk8s helm can connect into microk8s's k8s:

   /snap/bin/microk8s.helm3 ls

Or do this:
/snap/bin/helm --kubeconfig=/var/snap/microk8s/current/credentials/client.config ls


Misc notes:



Playing with installing hubble

```
SNAP_DATA=/var/snap/microk8s/current
SNAP_COMMON=/var/snap/microk8s/common

/snap/bin/microk8s.helm3 template cilium \
   --namespace kube-system \
   --set global.cni.confPath="$SNAP_DATA/args/cni-network" \
   --set global.cni.binPath="$SNAP_DATA/opt/cni/bin" \
   --set global.cni.customConf=true \
   --set global.containerRuntime.integration="containerd" \
   --set global.containerRuntime.socketPath="$SNAP_COMMON/run/containerd.sock" \
   --set global.nodeinit.enabled=true \
   --set global.kubeProxyReplacement=partial \
   --set global.hostServices.enabled=false \
   --set global.externalIPs.enabled=true \
   --set global.nodePort.enabled=true \
   --set global.hostPort.enabled=true \
   --set global.pullPolicy=IfNotPresent \
   --set config.ipam=kubernetes \
   --set global.hubble.enabled=true \
   --set global.hubble.listenAddress=":4244" \
   --set global.hubble.relay.enabled=true \
   --set global.hubble.ui.enabled=true
```


```
-> % sudo /snap/bin/microk8s.reset
Disabling all addons.
Disabling addon : ambassador
Disabling addon : cilium
Disabling addon : dashboard
Disabling addon : dns
Disabling addon : fluentd
Disabling addon : gpu
Disabling addon : helm
Disabling addon : helm3
Disabling addon : host-access
Disabling addon : ingress
Disabling addon : istio
Disabling addon : jaeger
Disabling addon : juju
Disabling addon : knative
Disabling addon : kubeflow
Disabling addon : linkerd
Disabling addon : metallb
Disabling addon : metrics-server
Disabling addon : multus
Disabling addon : prometheus
Disabling addon : rbac
Disabling addon : registry
Disabling addon : storage
All addons disabled.


#NOTE: enabling cilium disables flannel ...
sudo touch /var/snap/microk8s/current/var/lock/no-flanneld
```
