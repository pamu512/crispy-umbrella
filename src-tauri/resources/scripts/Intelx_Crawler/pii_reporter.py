import os
import pandas as pd
import re
from collections import Counter

def detect_pii_type(value):
    value = value.strip()
    
    # Once the UUID is matched, only file_systemid is returned
    if re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", value, re.IGNORECASE):
        return ["file_systemid"]

    types_detected = []
    if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", value):
        types_detected.append("email")
    if re.search(r"\+?\d[\d\s\-()]{7,}", value):
        types_detected.append("phone")
    if re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", value):
        types_detected.append("domain")
    if re.search(r"http[s]?://", value):
        types_detected.append("url")
    if re.search(r"^[A-Z][a-z]+(?:\s[A-Z][a-z]+)+$", value):
        types_detected.append("name")
    return types_detected

def auto_name_columns(df):
    column_names = []
    for col in df.columns:
        sample = df[col].dropna().astype(str).head(10)
        types = []
        for val in sample:
            types += detect_pii_type(val)
        most_common = Counter(types).most_common(1)
        name = most_common[0][0] if most_common else "unknown"
        index = len([c for c in column_names if name in c])
        column_names.append(f"{name}_{index}")
    df.columns = column_names
    return df

def extract_credentials(df):
    if "raw_line_0" in df.columns:
        creds = df["raw_line_0"].str.extract(r'(?P<url>https?://[^\s:]+):(?P<username>[^:]+):(?P<password>.+)')
        df = df.drop(columns=["raw_line_0"])
        df = pd.concat([creds, df], axis=1)
    return df

def process_csv_folder(target_folder):
    csv_folder = os.path.join("csv_output", target_folder)
    output_csv = f"{target_folder}.csv"

    if not os.path.exists(csv_folder):
        print(f"❌ Folder not found: {csv_folder}")
        return

    all_dataframes = []
    for filename in os.listdir(csv_folder):
        print("🔍 Processing file:", filename)
        if filename.endswith(".csv"):
            path = os.path.join(csv_folder, filename)
            df = pd.read_csv(path, header=None, skiprows=1, dtype=str, on_bad_lines='skip')

            df = auto_name_columns(df)

            # Change phone_0 to date_time
            renamed_columns = df.columns.tolist()
            for i, col in enumerate(renamed_columns):
                if col.startswith("phone_"):
                    renamed_columns[i] = "date_time"
                    break

            # Change file_systemid_* or unknown_* to file_systemid
            for i, col in enumerate(renamed_columns):
                if col.startswith("file_systemid_") or col.startswith("unknown_"):
                    renamed_columns[i] = "file_systemid"
                    break

            df.columns = renamed_columns
            df = extract_credentials(df)
            df.insert(0, "source_file", filename)
            all_dataframes.append(df)

    if not all_dataframes:
        print("⚠️ No CSV files processed.")
        return

    merged_df = pd.concat(all_dataframes, ignore_index=True)

    # Generate a PII tag column, leaving the source_file, date_time, and file_systemid fields blank
    pii_row = {}
    for col in merged_df.columns:
        if col in ["source_file", "date_time", "file_systemid"]:
            pii_row[col] = ""
        else:
            sample = merged_df[col].dropna().astype(str).head(10)
            detected = []
            for val in sample:
                detected += detect_pii_type(val)
            pii_row[col] = ", ".join(sorted(set(detected))) if detected else ""

    # Insert label column
    pii_df = pd.DataFrame([pii_row])
    final_df = pd.concat([pii_df, merged_df], ignore_index=True)

    # Fixed column order: source_file, date_time, filesystem are the first three columns
    columns = final_df.columns.tolist()
    ordered_cols = ["source_file", "date_time", "file_systemid"]
    remaining_cols = [col for col in columns if col not in ordered_cols]
    final_df = final_df[ordered_cols + remaining_cols]

    # Store the final DataFrame to a CSV file
    os.makedirs("final_report", exist_ok=True)
    final_df.to_csv(os.path.join("final_report", output_csv), index=False, encoding="utf-8-sig")

    print(f"✅ Output saved to: final_report/{output_csv}")
