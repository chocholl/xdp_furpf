bpftool net detach xdp dev ens19
rm -f /sys/fs/bpf/xdp_fw_kern_multi_map
rm -f /sys/fs/bpf/outer_hash
rm -f /sys/fs/bpf/_*
