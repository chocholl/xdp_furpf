bpftool -d prog load xdp_fw_kern_multi_map.o /sys/fs/bpf/xdp_fw_kern_multi_map
bpftool net attach xdp pinned /sys/fs/bpf/xdp_fw_kern_multi_map dev ens19
