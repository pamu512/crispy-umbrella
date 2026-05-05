import requests
import json
import csv
import os
from dotenv import load_dotenv
load_dotenv()

def json_to_csv(data, csv_file_path):

    results = data.get('results', [])
    
    # Define the header columns of the CSV
    headers = ['date', 'victim', 'domain', 'country', 'summary', 'title', 'url', 'ransomware_group']
    os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)
    with open(csv_file_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

        for item in results:
            row = {
                'date': item.get('date'),
                'victim': item.get('victim'),
                'domain': item.get('domain'),
                'country': item.get('country'),
                'summary': item.get('summary'),
                'title': item.get('title'),
                'url': item.get('url')
            }

            ransom_info = item.get('ransomware')
            if ransom_info and isinstance(ransom_info, dict):
                row['ransomware_group'] = ransom_info.get('group', 'N/A')
            else:
                row['ransomware_group'] = 'None' 

            writer.writerow(row)

    print(f"✅Finished: {csv_file_path}")

def fetch_cyberattacks_and_save(api_key, params, year):
    url = "https://api-pro.ransomware.live/press/all"
    headers = {
        'accept': 'application/json',
        'X-API-KEY': api_key
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        json_to_csv(data, f'output/cyberattacks/cyberattacks_{year}.csv')

    except Exception as e:
        print(f"❌ Error: {e}")

def export_cyberattacks(year):
    MY_API_KEY = os.getenv("MY_API_KEY") 
    
    #parameters for filtering the data, you can adjust these as needed
    # country = ""  #e.g. FR, US


    params = {}
    if year:
        params['year'] = year

    fetch_cyberattacks_and_save(MY_API_KEY, params, year)