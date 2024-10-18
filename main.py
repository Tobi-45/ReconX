import cmd
import os
import platform
import subprocess
import shutil
import nmap
import time

from tools.fuzzer import fuzz, load_wordlist
from tools.http_ssl_tls import analyze_http_ssl_tls
from tools.link_scraper import find_urls_in_website

class ReconXConsole(cmd.Cmd):
    print(r"""
         _____                     __   __
        |  __ \                    \ \ / /
        | |__) |___  ___ ___  _ __  \ V /
        |  _  // _ \/ __/ _ \| '_ \  > <  
        | | \ \  __/ (_| (_) | | | |/ . \ 
        |_|  \_\___|\___\___/|_| |_/_/ \_\
    """)
    intro = "\n\033[1;32mWelcome to ReconX! Type help or ? to list commands.\033[0m"
    prompt = "\033[1;34m(ReconX) > \033[0m"

    # Command to list files and directories
    def do_ls(self, arg):
        """List files and directories in the current directory."""
        try:
            files = os.listdir(os.getcwd())
            print("\n".join(files))
        except Exception as e:
            print(f"Error: Unable to list files. {e}")

    # Command to move files or directories
    def do_mv(self, arg):
        """Move a file or directory. Usage: mv <source> <destination>"""
        try:
            source, destination = arg.split()
            shutil.move(source, destination)
            print(f"Moved {source} to {destination}")
        except Exception as e:
            print(f"Error: {e}")

    # Command to copy files or directories
    def do_cp(self, arg):
        """Copy a file or directory. Usage: cp <source> <destination>"""
        try:
            source, destination = arg.split()
            if os.path.isdir(source):
                shutil.copytree(source, destination)
            else:
                shutil.copy(source, destination)
            print(f"Copied {source} to {destination}")
        except Exception as e:
            print(f"Error: {e}")

    # Command to ping a target with live output
    def do_ping(self, target):
        """Ping a target IP or domain (e.g., ping google.com)"""
        if not target:
            print("Error: Please specify a target.")
            return

        param = '-n' if platform.system().lower() == 'windows' else '-c'
        default_requests = 5
        command = ['ping', param, str(default_requests), target]

        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            for line in iter(process.stdout.readline, ''):
                print(line.strip())
            process.stdout.close()
            process.wait()
        except Exception as e:
            print(f"Error: Unable to execute ping. {e}")

    # Command to exit the console
    def do_exit(self, arg):
        """Exit the console"""
        print("Goodbye!")
        return True

    # Main command for Web Scanning, Network Scan, and Reconnaissance options
    def do_reconx(self, arg):
        """Main menu for ReconX"""
        while True:
            print("\033[1;33m[1] Web Scanning")
            print("[2] Network Scan")
            print("[3] Reconnaissance")
            print("[4] Back\033[0m")

            choice = input("\033[1;34mChoose an option: \033[0m")

            if choice == "1":
                self.web_scanning_menu()
            elif choice == "2":
                self.network_scan_menu()
            elif choice == "3":
                self.reconnaissance_menu()
            elif choice == "4":
                break
            else:
                print("\033[1;31m[!] Invalid choice. Please select a valid option.\033[0m")

    # Web Scanning menu
    def web_scanning_menu(self):
        while True:
            print("\033[1;33m[1] Simple Scan")
            print("[2] Advance Scan")
            print("[3] Back")

            choice = input("\033[1;34mChoose an option: \033[0m")

            if choice == "1":
                self.simple_scan_menu()
            elif choice == "2":
                self.advanced_scan_menu()
            elif choice == "3":
                break
            else:
                print("\033[1;31m[!] Invalid choice. Please select a valid option.\033[0m")

    # Advanced Scan menu
    def advanced_scan_menu(self):
        while True:
            print("\033[1;33m[1] HTTP & Security Scan")
            print("[2] Website Link Scraper")
            print("[3] Back\033[0m")

            choice = input("\033[1;34mChoose an option: \033[0m")

            if choice == "1":
                print("\033[1;32mRunning HTTP & Security Scan...\033[0m")
                try:
                    analyze_http_ssl_tls()
                except Exception as e:
                    print(f"\033[1;31m[!] Error: {e}\033[0m")

            elif choice == "2":
                print("\033[1;32mRunning Website Link Scraper...\033[0m")
                try:
                    find_urls_in_website()
                except Exception as e:
                    print(f"\033[1;31m[!] Error: {e}\033[0m")

            elif choice == "3":
                break
            else:
                print("\033[1;31m[!] Invalid choice. Please select a valid option.\033[0m")

    # Network Scan menu with the integrated Port Scanner
    def network_scan_menu(self):
        while True:
            print("\033[1;33m[1] Network Scan")
            print("[2] DNS/IP Scan")
            print("[3] Back\033[0m")

            choice = input("\033[1;34mChoose an option: \033[0m")

            if choice == "1":
                target_ip = input("Enter the IP address to scan: ")

                def estimate_scan_time(ports_scanned, time_per_port):
                    """Function to estimate the scan time before it begins."""
                    estimated_time = ports_scanned * time_per_port
                    return estimated_time

                def scan_ports(ip):
                    try:
                        # Initialize the Nmap PortScanner
                        scanner = nmap.PortScanner()

                        # Set the number of well-known ports
                        ports_scanned = 1023  # Well-known ports (1-1023)
                        
                        # Use a basic heuristic to estimate the time per port (e.g., 0.005 seconds per port)
                        time_per_port = 0.005  # Example of a historical average
                        estimated_total_time = estimate_scan_time(ports_scanned, time_per_port)
                        
                        print(f"Estimated total time for scanning well-known ports (1-1023): {estimated_total_time:.2f} seconds.")
                        input("Press Enter to start the scan...")

                        print(f"\nScanning IP: {ip} for well-known ports (1-1023) and services...\n")
                        
                        # Start the timer for actual scan
                        start_time = time.time()

                        # Scanning well-known ports (1-1023) with version detection
                        scanner.scan(ip, '1-1023', '-sV')

                        # Check if the scan returned results
                        if 'scan' not in scanner or ip not in scanner['scan']:
                            print(f"No results for IP: {ip}. The host might be unreachable or down.")
                            return

                        # Calculate how long the scan actually took
                        scan_time = time.time() - start_time
                        print(f"\nScan completed in {scan_time:.2f} seconds.\n")

                        # Loop through the results and print the details of open ports and services
                        for proto in scanner[ip].all_protocols():
                            ports = scanner[ip][proto].keys()
                            for port in ports:
                                service = scanner[ip][proto][port]
                                print(f"Port: {port}/tcp")
                                print(f"  Service: {service['name']}")
                                print(f"  Version: {service.get('version', 'unknown')}")
                                print(f"  Product: {service.get('product', 'unknown')}")
                                print(f"  Extra Info: {service.get('extrainfo', 'N/A')}")
                                print()

                    except nmap.PortScannerError as e:
                        print(f"Nmap error: {e}")
                    except Exception as e:
                        print(f"An error occurred: {e}")
                    finally:
                        total_time = time.time() - start_time
                        print(f"\nTotal time taken: {total_time:.2f} seconds.")

                try:
                    # Basic validation for IPv4 format
                    ip_segments = target_ip.split('.')
                    if len(ip_segments) != 4 or not all(0 <= int(segment) < 256 for segment in ip_segments):
                        raise ValueError("Invalid IP address format.")

                    scan_ports(target_ip)
                
                except ValueError as ve:
                    print(f"Error: {ve}")

            elif choice == "2":
                print("DNS/IP Scan selected...")
            elif choice == "3":
                break
            else:
                print("\033[1;31m[!] Invalid choice. Please select a valid option.\033[0m")

    # Reconnaissance menu
    def reconnaissance_menu(self):
        while True:
            print("\033[1;33m[1] SearchSploit")
            print("[2] Encryption/Decryption & Hashing")
            print("[3] Back\033[0m")

            choice = input("\033[1;34mChoose an option: \033[0m")

            if choice == "1":
                print("SearchSploit selected...")
            elif choice == "2":
                print("Encryption/Decryption & Hashing selected...")
            elif choice == "3":
                break
            else:
                print("\033[1;31m[!] Invalid choice. Please select a valid option.\033[0m")


if __name__ == '__main__':
    ReconXConsole().cmdloop()
