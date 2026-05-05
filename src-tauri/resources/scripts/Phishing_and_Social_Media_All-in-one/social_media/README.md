# Social Media Search Tool

A comprehensive social media search tool that uses Tor proxy service for anonymous searching with privacy protection features. This tool searches across multiple social media platforms (Facebook, Twitter, Instagram, LinkedIn, TikTok, Pinterest) and exports results to CSV files.

## Features

- **Multi-Platform Search**: Search across Facebook, Twitter, Instagram, LinkedIn, TikTok, and Pinterest
- **Tor Proxy Integration**: Anonymous searching with automatic Tor identity switching
- **Date Range Filtering**: Filter search results by date range (start_time and end_time)
- **Automatic Parameter Updates**: Intelligent CSE parameter retrieval and refresh
- **Docker Support**: Easy deployment with Docker Compose
- **Comprehensive Logging**: Detailed execution logs and session tracking
- **CSV Export**: Results exported to organized CSV files

## System Requirements

- **Docker** and **Docker Compose** (for Docker deployment)
- **Python 3.8+** (for local development)
- **Tor Browser** or **Tor Service** (for anonymous searching)

## Quick Start

### Method 1: Using Docker (Recommended)

#### Prerequisites

1. Install Docker and Docker Compose
   - Docker Desktop: [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
   - Or install Docker Engine and Docker Compose separately

#### Running with Docker Scripts

**Windows (PowerShell):**
```powershell
.\docker-run.ps1 -TargetName "your_keyword" -OutputPath "./output" -StartTime "2026-01-01" -EndTime "2026-01-31"
```

**Linux/macOS (Bash):**
```bash
./docker-run.sh your_keyword ./output 2026-01-01 2026-01-31
```

**Parameters:**
- `target_name` (required): Search keyword or target name
- `output_path` (optional): Output directory path (default: `./output`)
- `start_time` (optional): Start date in format `YYYY-MM-DD` (e.g., `2026-01-01`)
- `end_time` (optional): End date in format `YYYY-MM-DD` (e.g., `2026-01-31`)

**Examples:**

```powershell
# Basic search
.\docker-run.ps1 -TargetName "natixis"

# With custom output path
.\docker-run.ps1 -TargetName "natixis" -OutputPath "C:\Users\YourName\Desktop\results"

# With date range
.\docker-run.ps1 -TargetName "natixis" -StartTime "2026-01-01" -EndTime "2026-01-31"

# All parameters
.\docker-run.ps1 -TargetName "natixis" -OutputPath "./output" -StartTime "2026-01-01" -EndTime "2026-01-31"
```

```bash
# Basic search
./docker-run.sh natixis

# With custom output path
./docker-run.sh natixis /home/user/Desktop/results

# With date range
./docker-run.sh natixis ./output 2026-01-01 2026-01-31
```

#### Manual Docker Compose Usage

```bash
# Set environment variables and run
export TARGET_NAME="your_keyword"
export OUTPUT_PATH="/app/output"
export START_TIME="2026-01-01"
export END_TIME="2026-01-31"

# Run with Docker Compose
docker-compose run --rm main
```

### Method 2: Local Development

#### Environment Setup

1. **Install Tor Browser** (Recommended)
   - Visit [Tor Project Official Website](https://www.torproject.org/download/)
   - Download and install Tor Browser for your operating system
   - Launch Tor Browser and keep it running

2. **Setup Python Environment**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### Alternative: System Tor Service

**macOS:**
```bash
# Install using Homebrew
brew install tor

# Start Tor service
brew services start tor
```

**Ubuntu/Debian:**
```bash
# Install Tor
sudo apt update
sudo apt install tor

# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor
```

**Windows:**
```bash
# Install using Chocolatey
choco install tor

# Or manually download and install Tor Expert Bundle
```

#### Running the Application

```bash
# Activate virtual environment
source venv/bin/activate

# Run main program
python main.py
```

**Command Line Options:**
```bash
# With arguments
python main.py -v1 "your_keyword" -v2 "./output" -n 100

# Options:
# -v1, --target: Search target name (keyword)
# -v2, --output: Output directory path
# -n, --num: Number of results per platform (default: 100)
# --no-update-params: Skip getting latest CSE parameters
```

## Usage Instructions

### Basic Workflow

1. **Ensure Tor Service is Running**:
   - Tor Browser: Keep Tor Browser open
   - System Tor: Ensure Tor service is running

2. **Execute Search**:
   - The program will prompt for search keywords (in interactive mode)
   - Select the number of results to fetch for each platform
   - The program automatically searches across all supported platforms

3. **View Results**:
   - Results are saved in the `output/` folder (or specified output path)
   - Each platform's results are stored as separate CSV files
   - Files are organized by target name: `output/<target_name>/<target_name>_<platform>.csv`

### Date Range Filtering

When using `start_time` and `end_time` parameters:

- **Format**: `YYYY-MM-DD` (e.g., `2026-01-01`)
- **Purpose**: Filter search results to only include content within the specified date range
- **Usage**: Pass these parameters through Docker scripts or environment variables

**Note**: Date filtering is applied during the search process. Ensure your CSE parameters support date-based sorting.

## Advanced Features

### Automatic TOR Identity Switching & Token Refresh

The program includes intelligent retry mechanisms:

- **Automatic Detection**: Triggers when fetched results are less than 10 items
- **Identity Switching**: Executes TOR new identity switching
- **Token Refresh**: Automatically obtains latest CSE parameters
- **Re-fetch**: Uses new parameters to re-fetch current page data
- **Ensure Completeness**: Avoids data loss, maintains complete results per platform

### Using Tor Parameters

To use Tor proxy when obtaining CSE parameters:

```bash
# Use Tor proxy to get parameters
python getCSE.py --tor
```

### Environment Variables

The following environment variables can be set:

- `TARGET_NAME`: Search target name (keyword)
- `OUTPUT_PATH`: Output directory path (default: `/app/output` in container)
- `START_TIME`: Start date for filtering (format: `YYYY-MM-DD`)
- `END_TIME`: End date for filtering (format: `YYYY-MM-DD`)
- `TOR_SOCKS_HOST`: Tor SOCKS proxy host (default: `tor_docker` in Docker)
- `TOR_SOCKS_PORT`: Tor SOCKS proxy port (default: `9050`)

## Service Ports

- **Tor SOCKS Proxy**: `localhost:9150` (Tor Browser) or `localhost:9050` (System Tor)
- **Tor Control Port**: `localhost:9151` (Tor Browser) or `localhost:9051` (System Tor)

## Output Structure

Results are organized as follows:

```
output/
├── <target_name>/
│   ├── <target_name>_facebook.csv
│   ├── <target_name>_twitter.csv
│   ├── <target_name>_instagram.csv
│   ├── <target_name>_linkedin.csv
│   ├── <target_name>_tiktok.csv
│   └── <target_name>_pinterest.csv
```

## File Structure

```
├── requirements.txt           # Python dependencies
├── main.py                    # Main program entry point
├── getCSE.py                  # CSE parameter acquisition module
├── getSearchResult.py         # Search results module
├── cse_parameters.json        # CSE parameter cache file
├── platform_cse_parameters.json # Platform-specific parameter file
├── docker-compose.yml         # Docker Compose configuration
├── Dockerfile                 # Docker image definition
├── docker-run.ps1            # PowerShell Docker run script
├── docker-run.sh             # Bash Docker run script
├── output/                    # Output results folder
│   └── <target_name>/        # Folders organized by keywords
│       ├── <target_name>_facebook.csv
│       ├── <target_name>_twitter.csv
│       ├── <target_name>_instagram.csv
│       ├── <target_name>_linkedin.csv
│       ├── <target_name>_tiktok.csv
│       └── <target_name>_pinterest.csv
└── logs/                      # Log files
    ├── search_YYYYMMDD_HHMMSS.log
    └── search_log.json
```

## Troubleshooting

### Tor Connection Issues

```bash
# Check Tor service status
# macOS
brew services list | grep tor

# Linux
sudo systemctl status tor

# Test Tor proxy connection
curl --proxy socks5://127.0.0.1:9150 https://httpbin.org/ip
```

### Docker Issues

**Container fails to start:**
- Ensure Docker is running
- Check Docker Compose version: `docker compose version` or `docker-compose version`
- Verify `docker-compose.yml` syntax

**Tor service not ready:**
- Wait for health check to pass (up to 60 seconds)
- Check Tor container logs: `docker logs docker-tor`
- Verify network connectivity between containers

**Permission errors:**
- Ensure output directory is writable
- On Linux/macOS, check directory permissions: `ls -ld output/`
- On Windows, ensure you have write access to the output path

### Python Dependencies Issues

```bash
# Reinstall dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

### Port Conflicts

If ports 9150 or 9151 are occupied:

```bash
# Check port usage
# macOS/Linux
lsof -i :9150
lsof -i :9151

# Windows
netstat -ano | findstr :9150
netstat -ano | findstr :9151

# Kill occupying process (Linux/macOS)
sudo kill -9 <PID>
```

## Using Tor Proxy in Python

```python
import requests
from requests_tor import RequestsTor

# Using requests-tor
rt = RequestsTor()
response = rt.get('https://httpbin.org/ip')
print(response.json())

# Or using standard requests with proxy configuration
proxies = {
    'http': 'socks5://localhost:9150',
    'https': 'socks5://localhost:9150'
}
response = requests.get('https://httpbin.org/ip', proxies=proxies)
print(response.json())
```

## Important Notes

1. **Tor Service Must Be Running**: Ensure Tor Browser is open or system Tor service is started before running searches
2. **Network Connection**: First-time use requires internet connection to download browser drivers and dependencies
3. **Search Limitations**: Please comply with each platform's terms of use, avoid excessive frequent requests
4. **Data Privacy**: Search results are for personal research use only, please respect others' privacy
5. **Tor Startup Time**: Tor service requires a few seconds to establish connections (up to 40 seconds in Docker)
6. **Date Format**: When using date filtering, always use `YYYY-MM-DD` format (e.g., `2026-01-01`)
7. **Output Path**: Use absolute paths for best compatibility, especially in Docker environments

## Development Mode

During development:

```bash
# Keep Tor service running
# (Tor Browser or system service)

# Local development testing
source venv/bin/activate
python main.py

# Test specific modules
python getCSE.py --tor
python getSearchResult.py
```

## Supported Platforms

- **Facebook**: Via Social Searcher CSE
- **Twitter**: Via Social Searcher CSE  
- **Instagram**: Via Social Searcher CSE
- **LinkedIn**: Via Social Searcher CSE
- **TikTok**: Via Social Searcher CSE
- **Pinterest**: Via Social Searcher CSE

Each platform supports automatic parameter updates and intelligent retry mechanisms.

## License

This project is for educational and research purposes. Please ensure compliance with all applicable terms of service and regulations when using this tool.
