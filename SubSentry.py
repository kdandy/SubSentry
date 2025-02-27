import requests
import json
import dns.resolver
import whois
import pandas as pd
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import sublist3r  # Import Sublist3r directly

# Function to fetch subdomains from crt.sh (SSL scraping)
def get_subdomains_ssl(domain):
    print(f"Fetching subdomains from SSL database (crt.sh) for {domain}...")
    url = f"https://crt.sh/?q={domain}&output=json"
    
    for attempt in range(3):  # Retry 3 times
        try:
            response = requests.get(url, timeout=20)  # Increased timeout
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    subdomains = list(set(entry["name_value"] for entry in json_data))
                    return subdomains
                except ValueError:
                    print("⚠️ Unable to parse JSON from crt.sh!")
        except requests.exceptions.Timeout:
            print(f"⚠️ crt.sh request timed out. Retrying... ({attempt+1}/3)")
        except Exception as e:
            print(f"Error: {e}")
    
    return []

# Function to fetch subdomains using Sublist3r
def get_subdomains(domain):
    print(f"Fetching subdomains for {domain} using Sublist3r...")
    try:
        subdomains = sublist3r.main(
            domain=domain, 
            threads=40, 
            savefile=None, 
            ports=None, 
            silent=True, 
            verbose=False, 
            enable_bruteforce=False,
            engines=['VirusTotal', 'Google', 'Yahoo', 'Bing', 'Ask', 'Netcraft']
        )
        return subdomains if isinstance(subdomains, list) else []
    except Exception as e:
        print(f"Error: {e}")
        return []

# Function to check if a subdomain has a vulnerable CNAME record
def check_cname(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for rdata in answers:
            return str(rdata.target)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return None

# Function to determine if a subdomain is vulnerable to takeover
def check_takeover(subdomain):
    cname = check_cname(subdomain)
    if cname:
        if any(service in cname for service in ["amazonaws.com", "github.io", "herokuapp.com", "azurewebsites.net"]):
            return "Potential Takeover!"
        elif cname is None:
            return "Dangling Subdomain"
    return "Safe"

# Function to perform WHOIS lookup on a subdomain
def whois_lookup(domain):
    try:
        print(f"Performing WHOIS lookup for {domain}...")
        domain_info = whois.whois(domain)
        return "Available" if domain_info.get("status") is None else "Registered"
    except Exception:
        print("⚠️ WHOIS lookup failed. Trying alternative API...")
        try:
            response = requests.get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=YOUR_API_KEY&domainName={domain}&outputFormat=json", timeout=10)
            if response.status_code == 200:
                whois_data = response.json()
                return "Available" if "available" in whois_data else "Registered"
        except Exception:
            pass  # If alternative API also fails, return "Unknown"
    return "Unknown"

# Function to check if a subdomain is protected by Cloudflare
def check_cloudflare(subdomain):
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        headers = response.headers
        if "server" in headers and "cloudflare" in headers["server"].lower():
            return "Protected by Cloudflare"
    except requests.exceptions.RequestException:
        return "Not Cloudflare"
    return "Not Cloudflare"

# AI Model for takeover prediction
def train_ai_model(data):
    if data.empty:
        print("⚠️ No subdomains found, skipping AI training.")
        return None, None
    print("Training AI model for subdomain takeover prediction...")
    encoder = LabelEncoder()
    data["Status_Encoded"] = encoder.fit_transform(data["Status"])
    mapping = {"Protected by Cloudflare": 0, "Not Cloudflare": 1}
    data["Cloudflare_Protection"] = data["Cloudflare_Protection"].map(mapping).fillna(2).astype(int)
    whois_mapping = {"Available": 1, "Registered": 0, "Unknown": 2}
    data["WHOIS_Status"] = data["WHOIS_Status"].map(whois_mapping).fillna(2).astype(int)
    X = data[["Cloudflare_Protection", "WHOIS_Status"]]
    y = data["Status_Encoded"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    accuracy = model.score(X_test, y_test)
    print(f"✅ Model Accuracy: {accuracy:.2f}")
    return model, encoder

if __name__ == "__main__":
    target_domain = input("Enter target domain (e.g., example.com): ")
    subdomains_sublister = get_subdomains(target_domain)
    subdomains_ssl = get_subdomains_ssl(target_domain)
    subdomains = list(set(subdomains_sublister + subdomains_ssl))
    if not subdomains:
        print("⚠️ No subdomains found for this domain.")
        exit()
    results = []
    for sub in subdomains:
        time.sleep(1)
        status = check_takeover(sub)
        whois_status = whois_lookup(sub)
        cloudflare_status = check_cloudflare(sub)
        results.append({"Subdomain": sub, "Status": status, "WHOIS_Status": whois_status, "Cloudflare_Protection": cloudflare_status})
    df_results = pd.DataFrame(results)
    ai_model, label_encoder = train_ai_model(df_results)
    if ai_model:
        df_results["AI_Prediction"] = ai_model.predict(df_results[["Cloudflare_Protection", "WHOIS_Status"]])
    print("\n🔎 Subdomain Takeover Detection Results:\n")
    print(df_results.to_string(index=False))
    df_results.to_csv("subsentry_results.csv", index=False)
    print("\n✅ Results saved in 'subsentry_results.csv'")
