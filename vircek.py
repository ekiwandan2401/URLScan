from termcolor import colored
import requests
import json
from datetime import datetime

def convert_timestamp(timestamp):
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def main():
    ascii_art = r"""
    ____       ________               __             ________              __  
   / __ \___  / __/ _____  ____  ____/ ___  _____   / ____/ /_  ___  _____/ /__
  / / / / _ \/ /_/ /_/ _ \/ __ \/ __  / _ \/ ___/  / /   / __ \/ _ \/ ___/ //_/
 / /_/ /  __/ __/ __/  __/ / / / /_/ /  __/ /     / /___/ / / /  __/ /__/ ,<   
/_____/\___/_/ /_/  \___/_/ /_/\__,_/\___/_/      \____/_/ /_/\___/\___/_/|_|  

BY : EKKY.ID
                                                                            
    """

    # Menampilkan teks ASCII dengan warna
    print(colored(ascii_art, 'green'))

    # Menampilkan pesan untuk meminta input dari pengguna
    input_text = input("Masukkan URL : ")

    cookies = {
        'new-privacy-policy-accepted': '1',
        '_ga_1R8YHMJVFG': 'GS1.1.1717665198.1.1.1717667561.0.0.0',
        '_ga': 'GA1.2.1001677320.1717665160',
        '_gid': 'GA1.2.1768099838.1719641243',
        '_ga_BLNDV9X2JR': 'GS1.1.1719641241.3.1.1719641605.0.0.0',
        '_gat': '1',
    }

    headers = {
        'accept': 'application/json',
        'accept-ianguage': 'en-US,en;q=0.9,es;q=0.8',
        'accept-language': 'en-US,en;q=0.9,id;q=0.8',
        'content-type': 'application/json',
        'dnt': '1',
        'priority': 'u=1, i',
        'referer': 'https://www.virustotal.com/',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36',
        'x-app-version': 'v1x274x0',
        'x-tool': 'vt-ui-main',
        'x-vt-anti-abuse-header': 'MTEzODk1MTcyNDgtWkc5dWRDQmlaU0JsZG1scy0xNzE5NjQxNjE2LjI4MQ==',
    }

    response = requests.get(f'https://www.virustotal.com/ui/domains/{input_text}', cookies=cookies, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        last_analysis_date = attributes.get("last_analysis_date")
        last_analysis_date_formatted = convert_timestamp(last_analysis_date) if last_analysis_date else "N/A"
        whois = attributes.get("whois")
        categories = attributes.get("categories", {})
        print(colored(f"========================================", 'cyan'))
        print(colored(f"Last Analysis Date: {last_analysis_date_formatted}", 'yellow'))
        print(colored(f"========================================", 'cyan'))
        print(colored(f"WHOIS Info:\n{whois}", 'yellow'))
        print(colored(f"========================================", 'cyan'))
        print(colored("Deffender yang di pakai :", 'yellow'))
        print(colored(f"----------------------------------------", 'cyan'))
        for provider, category in categories.items():
            print(colored(f"  {provider}: {category}", 'cyan'))
        print(colored(f"========================================", 'cyan'))
    else:
        print(colored("Error fetching data from VirusTotal API", 'red'))

if __name__ == "__main__":
    main()
