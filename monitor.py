import whois
import dns.resolver
import time
import json
import os
import re

DOMAIN = "derp.com"  # Replace with the domain you want to monitor
CHECK_INTERVAL = 3600 / 2 
DATA_FILE = "domain_data.json"
INITIAL_BACKOFF = 60  # Initial backoff time in seconds (1 minute)

def get_whois_data(domain):
    try:
        data = whois.whois(domain)
        if 'Socket not responding' in data.text:
            raise Exception("Socket not responding")
        
        # Remove the "Last update of whois database" line
        data.text = re.sub(r"Last update of whois database:.*\r\n", "", data.text)
        return data
    except Exception as e:
        print(f"WHOIS query failed: {e}")
        return None

# Sort the MX records to make comparison insensitive to order
def get_mx_records(domain):
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_records.append(rdata.exchange.to_text())
    except Exception as e:
        print(f"Error fetching MX records: {e}")
    return sorted(mx_records)

def load_previous_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_current_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

def check_for_changes(backoff_time=INITIAL_BACKOFF):
    current_data = {
        'whois': get_whois_data(DOMAIN),
        'mx_records': get_mx_records(DOMAIN)
    }

    # Sort the MX records to make comparison insensitive to order
    if current_data['whois'] is None:
        print(f"Retrying WHOIS query in {backoff_time} seconds...")
        time.sleep(backoff_time)
        check_for_changes(backoff_time * 2)
        return

    previous_data = load_previous_data()

    if previous_data:
        whois_changed = previous_data['whois'] != current_data['whois'].__dict__
        mx_changed = previous_data['mx_records'] != current_data['mx_records']

        if whois_changed or mx_changed:
            print(f"Changes detected for {DOMAIN}:")
            if whois_changed:
                print("\nWHOIS information has changed.")
                print("Previous WHOIS data:", previous_data['whois'])
                print("Current WHOIS data:", current_data['whois'].__dict__)
            if mx_changed:
                print("\nMX records have changed.")
                print("Previous MX records:", previous_data['mx_records'])
                print("Current MX records:", current_data['mx_records'])

    save_current_data({'whois': current_data['whois'].__dict__, 'mx_records': current_data['mx_records']})

if __name__ == "__main__":
    while True:
        check_for_changes()
        time.sleep(CHECK_INTERVAL)
