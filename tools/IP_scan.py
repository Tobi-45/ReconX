import nmap
import time

def scan_ports(ip):
    try:
        # Initialize the Nmap PortScanner
        scanner = nmap.PortScanner()

        print(f"Scanning IP: {ip} and services...\n")

        # Start the timer
        start_time = time.time()

        # Scanning well-known ports (1-1023) with version detection
        scanner.scan(ip, '1-1023', '-sV')

        # Check if the scan returned results
        if 'scan' not in scanner or ip not in scanner['scan']:
            print(f"No results for IP: {ip}. The host might be unreachable or down.")
            return

        # Calculate how long the scan took
        scan_time = time.time() - start_time
        print(f"\nScan completed in {scan_time:.2f} seconds.\n")

        # Estimate time per port
        ports_scanned = 1023  # Well-known ports
        time_per_port = scan_time / ports_scanned
        estimated_time = ports_scanned * time_per_port

        print(f"Estimated time per port: {time_per_port:.4f} seconds.")
        print(f"Estimated total time for scanning well-known ports: {estimated_time:.2f} seconds.\n")
        
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

if __name__ == '__main__':
    target_ip = input("Enter the IP address to scan: ")

    # Check if the IP format is valid
    try:
        # Basic validation for IPv4 format
        ip_segments = target_ip.split('.')
        if len(ip_segments) != 4 or not all(0 <= int(segment) < 256 for segment in ip_segments):
            raise ValueError("Invalid IP address format.")

        scan_ports(target_ip)
    
    except ValueError as ve:
        print(f"Error: {ve}")
