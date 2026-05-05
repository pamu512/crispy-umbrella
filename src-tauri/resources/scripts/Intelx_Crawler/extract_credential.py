import os
import pandas as pd


def extract_credentials_from_filtered(filename):
    input_path = 'filtered/' + filename + '_matched.csv'
    output_path = 'Credential/'+filename+'_credential.csv'

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    df = pd.read_csv(input_path, dtype=str, keep_default_na=False)
    df_out = df[["date_time","domain", "username or email", "password"]]
    df_out.to_csv(output_path, index=False, encoding="utf-8")

    print(f"✅ Saved {len(df_out)} rows to {output_path}")
