## Setup

We need two separate `cgroups`, one for the proxy server, and the other for the client process that needs to be captured. In this example, we are using `/sys/fs/cgroup/witprox` for the proxy and `/sys/fs/cgroup/redirect` for the client processes.

The `witprox.bpf.c` and `redirect.bpf.c` contain the functions to be attached for these cgroups. 

Both these programs share three common maps, the `client_map (ClientSockCookie -> OrigInfo{...})`, `t_2_c (4tuple -> ClientSockCookie)`, and `server_map (ServerSockCookie -> OrigInf{...})`. 

Upon client's `connect4()` and `sockops::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`, we populate the `client_map` and the `t_2_c` map entries. The `t_2_c` map entry is used to link the client's socket cookie with the server's socket cookie so that the proxy server can read the original connection info that was stored by the client. 

Upon the proxy's `sockops::BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`, we use `t_2_c` to populate `server_map`.

##  Build
```
clang -O2 -g -target bpf -c witprox.bpf.c -o witprox.o
clang -O2 -g -target bpf -c redirect.bpf.c -o redirect.o
```

## Load
```
bpftool prog loadall redirect.o /sys/fs/bpf/redirect
```

```
CLIENT_MAP=$(bpftool map show | awk '
/^[0-9]+:/ {
    id=$1;
    sub(":", "", id);
    for(i=1; i<=NF; i++) {
        if($i == "name") {
            mapname=$(i+1);
            if(mapname == "client_map") {
                print id;
                exit;
            }
            break;
        }
    }
}')

T_2_C=$(bpftool map show | awk '
/^[0-9]+:/ {
    id=$1;
    sub(":", "", id);
    for(i=1; i<=NF; i++) {
        if($i == "name") {
            mapname=$(i+1);
            if(mapname == "t_2_c") {
                print id;
                exit;
            }
            break;
        }
    }
}')

bpftool map pin id $CLIENT_MAP /sys/fs/bpf/client_map
bpftool map pin id $T_2_C /sys/fs/bpf/t_2_c
```

```
bpftool prog loadall witprox.o /sys/fs/bpf/witprox map name t_2_c pinned /sys/fs/bpf/t_2_c map name client_map pinned /sys/fs/bpf/client_map
```

```
SERVER_MAP=$(bpftool map show | awk '
/^[0-9]+:/ {
    id=$1;
    sub(":", "", id);
    for(i=1; i<=NF; i++) {
        if($i == "name") {
            mapname=$(i+1);
            if(mapname == "server_map") {
                print id;
                exit;
            }
            break;
        }
    }
}')

bpftool map pin id $SERVER_MAP /sys/fs/bpf/server_map
```

## Attach

```
bpftool cgroup attach /sys/fs/cgroup/redirect connect4 pinned /sys/fs/bpf/redirect/cgroup_connect4
bpftool cgroup attach /sys/fs/cgroup/redirect sock_ops pinned /sys/fs/bpf/redirect/sockops

bpftool cgroup attach /sys/fs/cgroup/witprox sock_ops pinned /sys/fs/bpf/witprox/sockops
```

