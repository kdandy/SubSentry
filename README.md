# 🚀 Automated Subdomain Takeover Detector

## 🔍 Overview
This tool automates the detection of vulnerable subdomains that can be taken over using AI-driven analysis. It performs subdomain enumeration, CNAME checking, WHOIS lookup, Cloudflare protection analysis, and uses machine learning to predict potential takeovers.

## ✨ Features
- 🔎 **Subdomain Enumeration**: Uses Sublist3r and SSL scraping (crt.sh) to find subdomains.
- 🔗 **CNAME Analysis**: Detects abandoned services and misconfigured subdomains.
- 📝 **WHOIS Lookup**: Checks the registration status of domains.
- 🛡 **Cloudflare Detection**: Identifies whether a subdomain is protected by Cloudflare.
- 🤖 **AI-Based Prediction**: Uses a trained machine learning model to predict takeover risks.

## ⚙️ Installation
### Prerequisites
- 🐍 Python 3.x
- 🛠 Git
- 📦 Pip

### Install Dependencies
Clone the repository and install dependencies:
```sh
# Clone the repository
git clone https://github.com/kdandy/SubSentry.git
cd SubSentry

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # For macOS/Linux
.venv\Scripts\activate    # For Windows

# Install required dependencies
pip install -r requirements.txt
```
If `sublist3r` fails to install, try manually installing it:
```sh
pip install git+https://github.com/aboul3la/Sublist3r.git
```

## 🚀 Usage
Run the script and enter a target domain:
```sh
python SubSentry.py
```
Results will be saved in `subsentry_results.csv`.

## 📊 Example Output
| 🌐 Subdomain       | ⚠️ Status             | 🔍 WHOIS_Status | 🛡 Cloudflare_Protection | 🤖 AI_Prediction        |
|--------------------|----------------------|----------------|--------------------------|------------------------|
| test.example.com  | ⚠️ Potential Takeover! | ✅ Available    | ❌ Not Cloudflare       | 🔴 High Risk           |
| api.example.com   | ✅ Safe               | 🔒 Registered   | 🛡 Protected by Cloudflare | 🟢 Low Risk           |

## 🤝 Contribution
Feel free to fork this repository and submit pull requests to improve the tool.

## ⚠️ Disclaimer
This tool is for **educational and security research purposes only**. Unauthorized use on domains you do not own is illegal.

## 📜 License
📝 MIT License