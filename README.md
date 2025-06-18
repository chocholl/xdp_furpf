# xdp_urpf

## Info

Pretty fast XDP-based URPF implementation that leverages hierarchical data structures to perform high-speed packet filtering.
Two lookups are in use; the first one, keyed with the source MAC address, brings a pointer to the LPM table containing prefix-list entries to perform a second, source IP-based lookup.

Along with URPF, it supports ARP/NDP spoofing prevention and policing legitimate traffic with the TCP friendly single-rate policer.

Cloud service providers might find it useful to enforce security policies by restricting virtual machines from spoofing source addresses with no computational overhead.

## Filtering principles

It uses two tables to enforce source verification.

* SRC MAC to SRC IPv4 prefix-list

* SRC MAC to SRC IPv6 prefix-list

## Filtering rules

* Drop IPv4/IPv6 packet if SRC MAC is unknown.

* Drop IPv4/IPv6 packet if SRC IP is missing in the MAC specific prefix-list.

* Drop ICMPv6-NA is SRC Address doesn't match to ND Target Address (see https://datatracker.ietf.org/doc/html/rfc4861#section-4.4)

* Drop ARP if Sender IP doesn't match IPv4 prefix-list


## Compile and Attach to NIC

```
cd repo_dir
make
bash ./attach
```

## Binding to NIC/vNIC/TAP
```
bpftool -d prog load xdp_fw_kern_multi_map.o /sys/fs/bpf/xdp_fw_kern_multi_map
bpftool net attach xdp pinned /sys/fs/bpf/xdp_fw_kern_multi_map dev ens19
```

## Prefix-list editing

Prefix-lists are stored in text files with lines representing individual allowed source networks a given VM may use.

```
cat ./2d-8d-16-ca.acl
10.18.0.248/29
192.168.4.0/24

cat ff-26-37-ca.acl.v6
2a04:f901:a:7d:ffff:ffff:ffff:fffe/128

cat 2d-8d-16-ca.acl.v6
2a04:f901:b:7d::/64
```

Having prefix-list prepared just run CLI script which updates in-kernel data-structures.
In order to add entries run the following command
```
python3 update_map.py --mac f0-1c-2d-8d-16-ca --command add --file ./2d-8d-16-ca.acl --interface_index 3 --cir 150

python3 update_map_v6.py --mac d4-04-ff-26-37-ca --file ./ff-26-37-ca.acl.v6 --command add --interface_index 3 --cir 100
```

In order to delete entries run the following command
```
python3 update_map.py --mac f0-1c-2d-8d-16-ca --command del

python3 update_map_v6.py --mac f0-1c-2d-8d-16-ca --command del
```


## Further development

Open for ideas.
