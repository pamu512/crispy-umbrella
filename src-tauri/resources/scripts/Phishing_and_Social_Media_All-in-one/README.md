# Brand Scout

Brand Scout is a comprehensive tool for Brand Abuse Protection and Intelligence Gathering. It combines Phishing Scans (PS), Social Media Scans (SMS), and automated screenshotting into a unified Dockerized environment.

## Features

- **Phishing Scan (PS)**: Detects potential phishing domains using permutation generation and WHOIS/DNS analysis.
- **Social Media Scan (SMS)**: Scans social media platforms (Twitter, Facebook, etc.) for brand mentions.
- **Screenshotting**: Automatically captures screenshots of identified phishing domains and suspicious social media URLs.
- **Interactive & Automation**: Supports both interactive queries and automated CLI execution.

## Installation

### Prerequisites

- Docker
- Docker Compose

### Build the Docker Image

```bash
docker build -t br0k3nm1rr0r/brand-scout .
```

## Usage

You must run the container in privileged mode to enable Docker-in-Docker functionality.

### Interactive Mode

To start the interactive wizard:

```bash
docker run --privileged --rm -v ".:/workdir" -it br0k3nm1rr0r/brand-scout
```

You will be prompted to choose a scan type:

1. **PS (Phishing Scan)**: Requires Domain(s) (comma-separated), Start Date, End Date.
2. **SMS (Social Media Scan)**: Requires Keyword(s) (comma-separated), Start Date, End Date.
3. **ALL**: Runs both scans.

### Automated Mode

To run all scans non-interactively:

```bash
docker run --privileged --rm -v ".:/workdir" -it br0k3nm1rr0r/brand-scout \
    -all <DOMAIN> <KEYWORD> <START_DATE> <END_DATE>
```

To run isolated scans non-interactively:

```bash
# Phishing Scan Only
docker run --privileged --rm -v ".:/workdir" -it br0k3nm1rr0r/brand-scout \
    -ps "abc.com" "2024-01-01" "2024-12-31"

# Social Media Scan Only
docker run --privileged --rm -v ".:/workdir" -it br0k3nm1rr0r/brand-scout \
    -sms "natixis" "2024-01-01" "2024-12-31"
```

**Example (ALL):**

```bash
docker run --privileged --rm -v ".:/workdir" -it br0k3nm1rr0r/brand-scout \
    -all "natixis.com, abc.com" "natixis, abc" "2024-01-01" "2024-12-31"
```

## Output

All results are saved to the mounted working directory (`./` on host):

- **Phishing Results**: Generated inside domain-specific directories (e.g., `./<domain>/`), including `<domain>_permutations.csv`, `<domain>_permutations_lookup.csv`, and `<domain>_phish_results.csv`.
- **Social Media Results**: Generated inside keyword-specific subdirectories (e.g., `./social_media_output/<keyword>/`).
- **Screenshots**: `screenshots_output/` directory containing PNG captures of domains and URLs.

## Running on the host (outside Docker)

`brand_scout.py` resolves `social_media/docker-run.sh` and the `screenshots` package from the **directory that contains `brand_scout.py`**, not from `/app/...`. Use a venv with `pip install -r requirements.txt`, keep your working directory writable, and ensure Docker is available for steps that call `docker-run.sh` or `domain-sift`.

## Phishing domains (FQDN)

Permutation tools (e.g. dnstwist) need a **fully qualified domain** such as `lalamove.com`, not a bare brand like `Lalamove`. See `targets.example.env` for notes. The script will warn and append `.com` if a domain token has no dot (override by passing the correct TLD).

## Troubleshooting

- **Permissions**: Ensure your local directory is writable.
- **Privileged Mode**: If you see Docker daemon errors, ensure you are using `--privileged`.

