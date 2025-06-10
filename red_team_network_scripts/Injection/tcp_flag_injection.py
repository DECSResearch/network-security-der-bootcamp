import argparse
import sys
import subprocess
import shlex

DEBUG = False

def list_of_tcp_flags(flag):
    flags=[]
    hashmap={
        1:'FIN',
        2:'SYN',
        4:'RST',
        8:'PSH',
        16:'ACK',
        32:'URG'
    }
    binary_flag=str(bin(flag)[2:])
    for i in range(len(binary_flag)):
        if binary_flag[i] == '1':
            flags.append(hashmap[2**(len(binary_flag)-i-1)])
            
    return flags

def tcp_flag_injection(ip_addr, port, flag):
    flags=list_of_tcp_flags(flag)
    if len(flags) == 0:
        print("No TCP flags set. Exiting...")
        return False
    
    if DEBUG: print (f"TCP flags to inject: {flags}.. Generating Nmap command")
    
    port_spec = "1-65535" if port == -1 else str(port)
    flags_str = ",".join(flags)
    
    command = f"sudo nmap -sS --scanflags {flags_str} -p {port_spec} {ip_addr}"
    
    success=run_nmap(command)

    return success

def run_nmap(command):
    if DEBUG:
        print("Generated Nmap command:")
        print(command)
    try:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True, check=True)
        if DEBUG:
            print("Nmap command output:")
            print(result.stdout)
        if result.stderr:
            if DEBUG: print(f'Nmap command error: {result.stderr}')
            return False
        else:
            return True
                       
            
    except subprocess.CalledProcessError as e:
        print("Error running Nmap command:")
        print(e.stderr)
    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TCP flag injection attack')
    parser.add_argument('ip_addr', help='IP of target')
    parser.add_argument('-p', '--port', default=-1, type=int, help='Port of target')
    parser.add_argument('-f','--flag', type=int, help='TCP flag code to inject')
    parser.add_argument('-d', '--debug', default=False, action='store_true',
                       help='Debug mode')
    
    args = parser.parse_args()
    ip_addr = args.ip_addr
    port = args.port
    flag = args.flag
    DEBUG = args.debug
    
    if port < -1 or port > 65535:
        print("Invalid port value. Must be an integer between 0 and 65535.")
        sys.exit(1)
        
    if flag < 0 or flag > 63:
        print("Invalid flag value. Must be an integer between 0 and 63.")
        sys.exit(1)

    if DEBUG:
        print(f"Debugging mode enabled. Target IP: {ip_addr}, Port: {port}, Flag: {flag}")

    print(f'Starting TCP flag injection attack on {ip_addr} with flag {flag}')
    
    success = tcp_flag_injection(ip_addr, port, flag)
    
    if success:
        print(f"SUCCESS: TCP flag injection attack on {ip_addr} with flag {flag} completed successfully.")
    else:
        print(f"FAILED: TCP flag injection attack on {ip_addr} with flag {flag} failed.")
    sys.exit(1)