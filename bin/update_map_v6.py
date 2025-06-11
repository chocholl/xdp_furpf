import subprocess
import ast
import argparse
import ipaddress
import netaddr

MAP_PREFIX = '_'

def f_ip(n_addr):
    ret = []
    for b in n_addr.ip.bits().split(':'):
        b1 = b[0:8]
        b2 = b[8:16]
        ret.append(f'{hex(int(b1, 2))}' + ' ' + f'{hex(int(b2, 2))}')
    return ' '.join(ret)

def f_bw(n_addr):
    ret = []
    for b in n_addr.ip.bits().split('.'):
        ret.append(f'{hex(int(b, 2))}')
    return ' '.join(ret)

def f_mac(n_mac):
    return f'{n_mac.split("-")[-4]} {n_mac.split("-")[-3]} {n_mac.split("-")[-2]} {n_mac.split("-")[-1]}'

parser = argparse.ArgumentParser()
parser.add_argument('--mac', help='mac address in HEX format xx-xx-xx-xx-xx-xx', required=True)
parser.add_argument('--file', help='access control entries file name')
parser.add_argument('--command', help='add/delete action to take', required=True)
parser.add_argument('--interface_index', help='interface index to bind acl to, please see "ip link show" output')
parser.add_argument('--cir', help='max bytes per second allowed')
args = parser.parse_args()

table_name = args.mac.replace('-', '')

if args.command == 'del':
    cli_command = f'bpftool map delete name outer_hash_v6 key hex {f_mac(args.mac)}'
    subprocess.check_output(cli_command, shell=True, text=True)

    cli_command = f'rm /sys/fs/bpf/{MAP_PREFIX}_{table_name}'
    subprocess.check_output(cli_command, shell=True, text=True)

    try:
        cli_command = f'bpftool map delete name cir key hex {f_mac(args.mac)}'
        subprocess.check_output(cli_command, shell=True, text=True)
    except Exception:
        pass

if args.command == 'add':
    cli_command = f'bpftool map create /sys/fs/bpf/{MAP_PREFIX}_{table_name} type lpm_trie key 20 value 1 entries 20 flags 1 name {MAP_PREFIX}_{table_name}'
    print(cli_command)
    subprocess.check_output(cli_command, shell=True, text=True)

    cli_command = f'bpftool -j map show name {MAP_PREFIX}_{table_name}'
    print(cli_command)
    system_output = subprocess.check_output(cli_command, shell=True, text=True)
    inner_map = ast.literal_eval(system_output)

    with open(args.file, 'r') as file:
        for line in file:
            ip_network = ipaddress.ip_network(line.strip())
            ip_network = netaddr.IPNetwork(line.strip())

            n_addr = ip_network
            p_len = ip_network.prefixlen
            cli_command = f'bpftool map update id {inner_map["id"]} key hex {hex(p_len)} 00 00 00 {f_ip(n_addr)} value hex {hex(int(args.interface_index))}'
            print(cli_command)
            subprocess.check_output(cli_command, shell=True, text=True)

    cli_command = f'bpftool map update pinned /sys/fs/bpf/outer_hash_v6 key hex {f_mac(args.mac)} value id {inner_map["id"]}'
    print(cli_command)
    subprocess.check_output(cli_command, shell=True, text=True)

    if args.cir:
        cir = int(args.cir)
        dec_ip = netaddr.IPNetwork(netaddr.IPAddress(cir))
        bits = f_bw(dec_ip).split(' ')
        bits.reverse()
        bw_hex = ' '.join(bits)
        cli_command = f'bpftool map update pinned /sys/fs/bpf/cir key hex {f_mac(args.mac)} value hex {bw_hex}'
        print(cli_command)
        subprocess.check_output(cli_command, shell=True, text=True)
