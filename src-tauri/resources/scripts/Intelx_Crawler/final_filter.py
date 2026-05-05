import pandas as pd
import re

from credential_sanitizer import (
    clean_domain,
    clean_username,
    clean_password,
    is_likely_password
)

def extract_credentials_from_any_column(input_csv, output_csv, target_id):
    df = pd.read_csv(input_csv, dtype=str, keep_default_na=False)

    matched_rows = []

    # regex patterns for matching credentials
    pattern_primary = re.compile(r"(https?://\S+)\s+([^\s:]+):([^\s]+)")
    pattern_url_email_pass = re.compile(r"((?:https?://)?\S+):([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+):([^\s,]+)")
    pattern_email_pass = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+):([^\s,]+)")
    pattern_domain_user_pass = re.compile(r"([a-zA-Z0-9_.-]+\.[a-zA-Z]{2,}):([^\s:]+):([^\s,]+)")

    for _, row in df.iterrows():
        full_text = " ".join([str(v) for v in row.values if pd.notna(v)])

        # Match https://domain username:password
        match = pattern_primary.search(full_text)
        if match:
            domain = clean_domain(match.group(1))
            user = clean_username(match.group(2), keep_blank_literal=False)
            pw = clean_password(match.group(3))

            if (not user) or (not is_likely_password(pw)):
                continue

            matched_rows.append({
                "source_file": row.get("source_file", ""),
                "date_time": row.get("date_time", ""),
                "file_systemid": row.get("file_systemid", ""),
                "raw_content": full_text,
                "domain": domain,
                "username or email": user,
                "password": pw,
                "match_source": "primary"
            })
            continue

        # Match domain:email:password
        match = pattern_url_email_pass.search(full_text)
        if match:
            domain = clean_domain(match.group(1))
            user = clean_username(match.group(2), keep_blank_literal=False)
            pw = clean_password(match.group(3))

            if (not user) or (not is_likely_password(pw)):
                continue

            matched_rows.append({
                "source_file": row.get("source_file", ""),
                "date_time": row.get("date_time", ""),
                "file_systemid": row.get("file_systemid", ""),
                "raw_content": full_text,
                "domain": domain,
                "username or email": user,
                "password": pw,
                "match_source": "url:email:pass"
            })
            continue


        # Match email:password
        match = pattern_email_pass.search(full_text)
        if match:
            domain = clean_domain(target_id)
            user = clean_username(match.group(1), keep_blank_literal=False)
            pw = clean_password(match.group(2))

            if (not user) or (not is_likely_password(pw)):
                continue

            matched_rows.append({
                "source_file": row.get("source_file", ""),
                "date_time": row.get("date_time", ""),
                "file_systemid": row.get("file_systemid", ""),
                "raw_content": full_text,
                "domain": domain,
                "username or email": user,
                "password": pw,
                "match_source": "email:pass"
            })
            continue


        # Match domain:username:password
        match = pattern_domain_user_pass.search(full_text)
        if match:
            domain = clean_domain(match.group(1))
            user = clean_username(match.group(2), keep_blank_literal=False)
            pw = clean_password(match.group(3))

            if (not user) or (not is_likely_password(pw)):
                continue

            matched_rows.append({
                "source_file": row.get("source_file", ""),
                "date_time": row.get("date_time", ""),
                "file_systemid": row.get("file_systemid", ""),
                "raw_content": full_text,
                "domain": domain,
                "username or email": user,
                "password": pw,
                "match_source": "domain:user:pass"
            })
            continue


    if matched_rows:
        output_df = pd.DataFrame(matched_rows)
        output_df["username or email"] = output_df["username or email"].apply(lambda x: f'"{x}"' if x.isdigit() else x)
        output_df["password"] = output_df["password"].apply(lambda x: f'"{x}"' if x.isdigit() else x)
        output_df["domain"] = output_df["domain"].replace("", target_id)
        output_df.to_csv(output_csv, index=False, encoding="utf-8-sig")
        print(f"✅ Exported matched results to: {output_csv}")
    else:
        print("⚠️ No credentials matched the given patterns.")
