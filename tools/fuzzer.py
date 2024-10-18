import requests
import sys

# Function to load the wordlist
def load_wordlist(wordlist_path):
    try:
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
        sys.exit(1)

# Directory fuzzing function
def fuzz_directories(base_url, wordlist):
    print("[*] Fuzzing directories...")
    for word in wordlist:
        url = f"{base_url}/{word}"
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] Found directory: {url}")

# Subdomain fuzzing function
def fuzz_subdomains(base_domain, wordlist):
    print("[*] Fuzzing subdomains...")
    for word in wordlist:
        subdomain = f"http://{word}.{base_domain}"
        try:
            response = requests.get(subdomain)
            if response.status_code == 200:
                print(f"[+] Found subdomain: {subdomain}")
        except requests.ConnectionError:
            pass

# Parameter fuzzing function
def fuzz_parameters(base_url, wordlist):
    print("[*] Fuzzing parameters...")
    for word in wordlist:
        url = f"{base_url}?{word}=test"
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[+] Potential parameter: {url}")

# Main fuzzing handler
def fuzz(target, fuzz_type, wordlist):
    if fuzz_type == "directories":
        fuzz_directories(target, wordlist)
    elif fuzz_type == "subdomains":
        fuzz_subdomains(target, wordlist)
    elif fuzz_type == "parameters":
        fuzz_parameters(target, wordlist)
    else:
        print("[!] Invalid fuzzing type selected.")
        sys.exit(1)

# Ask user for the required inputs
if __name__ == "__main__":
    target = input("Enter target URL or domain: ")
    fuzz_type = input("Enter fuzzing type (directories/subdomains/parameters): ")
    wordlist_path = input("Enter the wordlist file path: ")

    # Load the wordlist
    wordlist = load_wordlist(wordlist_path)

    # Start fuzzing
    fuzz(target, fuzz_type, wordlist)
