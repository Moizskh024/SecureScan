
# SecureScan

SecureScan is an educational cybersecurity project for URL validation, DNS-based destination preflight assessment, and HTTP security-header analysis.

## Features

- Validate URL formatting and protocols.
- Resolve hostnames and assess destination IP addresses against a security policy.
- Analyze manually supplied HTTP security headers.
- Display findings and download a JSON header-analysis report.
- Handle invalid inputs and API errors.

## Technology Stack

- Python
- Flask
- HTML, CSS, and JavaScript
- Python unittest

## Requirements

- Python 3.10 or a compatible version supported by the project dependencies
- pip

## Setup

1. Clone the repository.
2. Open a terminal in the project directory.
3. Create and activate a virtual environment.
4. Install the dependencies.
5. Start the application.

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Run Tests

```powershell
python -m unittest discover -s tests -v
```

## Security Notes

- URL validation does not connect to the target website.
- Preflight performs DNS-based assessment; DNS resolution can contact DNS infrastructure.
- The application does not make HTTP requests to user-submitted target websites.
- Header analysis evaluates supplied data only and does not measure overall website security.
- Preflight results are not a guarantee that a destination is safe.

## Disclaimer

This project is intended for educational and defensive cybersecurity use.
