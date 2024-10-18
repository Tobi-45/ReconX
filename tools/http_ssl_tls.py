import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def analyze_http_ssl_tls():
    # Ask the user to input the target URL
    url = input("Enter the target URL (e.g., https://example.com): ").strip()

    # Parse the URL and extract the domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

    # Check if URL starts with http/https, if not prepend "http://"
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        # Send a GET request to the target URL
        response = requests.get(url, timeout=10)

        # Get the response headers
        headers = response.headers

        # Display basic header information
        print("\nHTTP Header Analysis Results:")
        print("=" * 40)
        print(f"URL: {url}")
        print(f"Status Code: {response.status_code}")
        print(f"Server: {headers.get('Server', 'N/A')}")
        print(f"Content-Type: {headers.get('Content-Type', 'N/A')}")
        print(f"Date: {headers.get('Date', 'N/A')}")
        print(f"Cookies: {response.cookies}")
        print("=" * 40)

        # Security-related headers
        print("\nSecurity Headers:")
        print("=" * 40)
        security_headers = ['Strict-Transport-Security', 'Content-Security-Policy',
                            'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy',
                            'Permissions-Policy']

        for header in security_headers:
            print(f"{header}: {headers.get(header, 'Not Set')}")

        # Display any other relevant headers
        print("=" * 40)
        print("\nOther Useful Headers:")
        print("=" * 40)
        for key, value in headers.items():
            print(f"{key}: {value}")

        # Check for SSL/TLS certificate if the URL uses HTTPS
        if url.startswith('https://'):
            check_ssl_certificate(domain)
        else:
            print("\nNo SSL/TLS certificate found. The URL does not use HTTPS.")
    
    except requests.exceptions.RequestException as e:
        print(f"\nError: {e}")


def check_ssl_certificate(domain):
    try:
        print("\nSSL/TLS Certificate Information:")
        print("=" * 40)
        
        # Create an SSL context
        context = ssl.create_default_context()

        # Connect to the server using an SSL socket
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Extract relevant certificate information
                print(f"Issued To (Domain): {cert['subject']}")
                print(f"Issuer: {cert['issuer']}")
                print(f"Serial Number: {cert.get('serialNumber', 'N/A')}")
                print(f"Version: {cert.get('version', 'N/A')}")

                # Display validity dates
                not_before = cert['notBefore']
                not_after = cert['notAfter']
                print(f"Valid From: {datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')}")
                print(f"Valid Until: {datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')}")

                # Check for expiration
                expires_on = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                remaining_days = (expires_on - datetime.utcnow()).days
                print(f"Days Until Expiration: {remaining_days}")

                # Display SAN (Subject Alternative Names) if present
                san = cert.get('subjectAltName', 'N/A')
                print(f"Subject Alternative Names (SAN): {san}")
                
    except Exception as e:
        print(f"Error fetching SSL certificate: {e}")

if __name__ == "__main__":
    analyze_http_ssl_tls()
