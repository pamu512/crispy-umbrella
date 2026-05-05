import requests
from bs4 import BeautifulSoup
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

INPUT_FILE = "output_result/merged_cve_result.csv"
OUTPUT_FILE = "output_result/Exploited_POC_CVEs.csv"

session = requests.Session()
def get_cve_details_from_feedly(cve):
    session.proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }
    session.headers.update({
        "User-Agent": "Mozilla/5.0"
    })

    resp = session.get(
        f"https://feedly.com/cve/{cve}",
        timeout=20,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    time.sleep(0.3)
    resp.raise_for_status()
    if resp.status_code != 200:
        print(f"[-] {cve} not found on Feedly")
        return None

    doc = BeautifulSoup(resp.text, "html.parser")
    content = doc.find("script", {"id": "__NEXT_DATA__"})
    data = json.loads(content.string)

    cveInfo = data["props"]["pageProps"]["cveInfo"]
    if cveInfo.get("executiveSummary"):
        executiveSummary = cveInfo.get("executiveSummary")

        summary = executiveSummary["description"]
        impact = executiveSummary["impact"]
        mitigation = executiveSummary["mitigation"]
        Exploitation_POC_Note = executiveSummary["exploitation"]
        patch = executiveSummary["patch"]

        #Extract POC and Exploitation details
        Exploitation = "N/A"
        POC = "N/A"
        if "There is no evidence that a public proof-of-concept exists." in Exploitation_POC_Note:
            POC = "N/A"
        else:
            POC = cveInfo.get("proofOfExploits")

        if "There is no evidence of proof of exploitation at the moment." in Exploitation_POC_Note:
            Exploitation = "N/A"
            POC = ",".join(
                cveInfo.get("exploits", []) +
                cveInfo.get("proofOfExploits", [])
            )
            if POC == "":
                POC = "N/A"
        else:
            Exploitation = cveInfo.get("exploits")

        
        result = {
            "summary": summary,
            "impact": impact,
            "mitigation": mitigation,
            "Exploitation": Exploitation,
            "POC": POC,
            "Exploitation_POC_Note": Exploitation_POC_Note,
            "patch": patch,
        }
        return result
    else:
        return None



def load_cve_from_json():
    fields_to_extract = ["CVE ID", "Vendor", "Published Date", "Summary", "Impact", "Mitigation","Exploitation", "POC", "Exploitation_POC_Note", "Patch"]

    with open(INPUT_FILE, "r", encoding="utf-8") as infile, \
         open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as outfile:

        reader = csv.DictReader(infile)
        writer = csv.DictWriter(outfile, fieldnames=fields_to_extract)

        writer.writeheader()

        rows = list(reader) 
        print(f"[*] Total CVEs to process from Feedly: {len(rows)}")
        MAX_WORKERS = 5

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {
                executor.submit(
                    get_cve_details_from_feedly,
                    row["CVE ID"].strip()
                ): row
                for row in rows
            }

            for future in as_completed(future_map):
                row = future_map[future]
                cve_id = row["CVE ID"].strip()

                try:
                    cveInfo = future.result()
                except Exception as e:
                    print(f"[!] Error {cve_id}: {e}")
                    continue

                if cveInfo:
                    print(f"[+] Found exploited POC for {cve_id}")
                    writer.writerow({
                        "CVE ID": cve_id,
                        "Vendor": row.get("Vendor"),
                        "Published Date": row.get("Published Date"),
                        "Summary": cveInfo["summary"],
                        "Impact": cveInfo["impact"],
                        "Mitigation": cveInfo["mitigation"],
                        "Exploitation": cveInfo["Exploitation"],
                        "POC": cveInfo["POC"],
                        "Exploitation_POC_Note": cveInfo["Exploitation_POC_Note"],
                        "Patch": cveInfo["patch"],
                    })
                else:
                    print(f"[-] No exploited POC for {cve_id}")

                time.sleep(0.1) 



    print(f"[+] POC result saved to {OUTPUT_FILE}")

def Expolited_POC_start():
    print("========================================")
    print("[*] Starting Exploited POC search from Feedly ...")
    load_cve_from_json()
