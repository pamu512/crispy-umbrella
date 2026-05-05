import csv
import os
import tempfile
import pycountry

def country_code_to_name(code: str) -> str:
    if code is None:
        return ""
    code = str(code).strip()
    if not code:
        return ""

    c = pycountry.countries.get(alpha_2=code.upper())
    if c:
        return c.name

    c = pycountry.countries.get(alpha_3=code.upper())
    if c:
        return c.name

    if code.isdigit():
        c = pycountry.countries.get(numeric=code.zfill(3))
        if c:
            return c.name

    return code

def add_country_full(input_file: str, output_file: str, country_field: str = "country"):
    in_path = os.path.abspath(input_file)
    out_path = os.path.abspath(output_file)

    # 同名就走 temp file → replace
    same_file = (in_path == out_path)

    tmp_dir = os.path.dirname(out_path) or "."
    os.makedirs(tmp_dir, exist_ok=True)

    # 建立暫存檔（跟 output 同一個資料夾，確保 replace 原子性較好）
    fd, tmp_path = tempfile.mkstemp(prefix="._tmp_country_", suffix=".csv", dir=tmp_dir)
    os.close(fd)

    try:
        with open(input_file, "r", encoding="utf-8-sig", newline="") as infile, \
             open(tmp_path, "w", encoding="utf-8-sig", newline="") as outfile:

            reader = csv.DictReader(infile)
            if not reader.fieldnames:
                raise ValueError("CSV has no header/fieldnames.")

            if country_field not in reader.fieldnames:
                raise ValueError(
                    f"Country field '{country_field}' not found. Available fields: {reader.fieldnames}"
                )

            fieldnames = list(reader.fieldnames)

            # 確保 country_full 存在
            if "country_full" not in fieldnames:
                fieldnames.append("country_full")
            
            # 把 country_full 放到 country 後面
            if "country" in fieldnames and "country_full" in fieldnames:
                fieldnames.remove("country_full")
                country_idx = fieldnames.index("country")
                fieldnames.insert(country_idx + 1, "country_full")

            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                row["country_full"] = country_code_to_name(row.get(country_field))
                writer.writerow(row)

        # 寫完再覆蓋 output（同名就覆蓋原檔）
        os.replace(tmp_path, out_path)

    except Exception:
        # 出錯就清理暫存檔，避免留下垃圾
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        finally:
            raise

def transform_country_full(input_file: str, output_file: str):
    add_country_full(input_file, output_file, country_field="country")