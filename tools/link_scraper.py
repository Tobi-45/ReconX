import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def find_urls_in_website():
    # Ask the user to input the target URL
    url = input("Enter the target website URL (e.g., https://example.com): ").strip()

    # Check if URL starts with http/https, if not prepend "http://"
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        # Send a GET request to the target URL
        response = requests.get(url, timeout=10)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the HTML content
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all 'a' tags (links) in the HTML
            links = soup.find_all('a')

            # Extract and display the URLs
            print(f"\nFound {len(links)} links on the website:")
            print("=" * 40)
            for link in links:
                href = link.get('href')

                # Resolve relative URLs by joining with the base URL
                full_url = urljoin(url, href)

                print(full_url)

        else:
            print(f"Failed to retrieve the website. Status code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    find_urls_in_website()
