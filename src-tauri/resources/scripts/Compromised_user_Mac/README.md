## Installation

Install the required packages

Run the script with:

```bash
pip install -r requirements.txt
```

## Usage

Run the script with:

```bash
python main.py
```

### Input

The program will ask for two inputs:

### 1. Cookie

```
Please enter the new Cookie:
```

- If the target website requires authentication, enter a valid Cookie.
- If left empty, the script will use the default Cookie value currently defined in the headers.

### 2. Domains

```
Please enter the domains to be queried (e.g., example.com,test.com):
```

You can enter one or multiple domains separated by commas.

Example:

```
example.com, test.com
```

### Example Execution

```bash
$ python main.py
Please enter the new Cookie: your_cookie_here
Please enter the domains to be queried (e.g., example.com,test.com): example.com,test.com
Domains to be queried: ['example.com', 'test.com']
🔍 start...
Data has been successfully saved to logs/example_com_logs.csv
📂 store to logs/example_com_logs.csv
Data has been successfully saved to logs/test_com_logs.csv
📂 store to logs/test_com_logs.csv
✅ finished！
```

## Output

The script stores the query results in the `logs/` directory.

If the directory does not exist, it will be created automatically.

### Output File Naming Rule

Each queried domain will generate one CSV file:

```
logs/{domain_name}_logs.csv
```

For example:

```
logs/example_com_logs.csv
logs/test_com_logs.csv
```

### Output Fields

Each CSV file contains the following columns:

- `stealer`
- `target_link`
- `other_links`
- `Date / Size`

### Field Description

- **stealer**
    The name of the stealer associated with the log record.
- **target_link**
    Links that match the queried target domain.
- **other_links**
    Other links found in the same record that do not match the queried domain.
- **Date / Size**
    The normalized date and size value extracted from the original table field.

