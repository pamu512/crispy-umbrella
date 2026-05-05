import requests
import json
import csv
import os
from dotenv import load_dotenv
load_dotenv()

def json_to_csv(data, csv_file_path):

    results = data.get('victims', [])
    
    # Define the header columns of the CSV
    headers = ['id', 'discovered_date', 'attackdate', 'victim', 'group', 'description', 'post_url', 'country', 'activity', 'screenshot']
    os.makedirs(os.path.dirname(csv_file_path), exist_ok=True)
    with open(csv_file_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

        for item in results:
            row = {
                'id': item.get('id'),
                'discovered_date': item.get('discovered'),
                'attackdate': item.get('attackdate'),
                'victim': item.get('victim'),
                'group': item.get('group'),
                'description': item.get('description'),
                'post_url': item.get('post_url'),
                'country': item.get('country'),
                'activity': item.get('activity'),
                'screenshot': item.get('screenshot')
            }

            if row['post_url'] == "":
                row['post_url'] = "None"

            if row['screenshot'] == "":
                row['screenshot'] = "None"

            

            writer.writerow(row)

    print(f"✅Finished: {csv_file_path}")

def fetch_victims_and_save(api_key, year):
    url = f"https://api-pro.ransomware.live/victims/?year={year}"
    headers = {
        'accept': 'application/json',
        'X-API-KEY': api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        json_to_csv(data, f'output/victims/victims_{year}.csv')

    except Exception as e:
        print(f"❌ Error: {e}")

def export_victims(year):
    MY_API_KEY = os.getenv("MY_API_KEY") 

    fetch_victims_and_save(MY_API_KEY, year)