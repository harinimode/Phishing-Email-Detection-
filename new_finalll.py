import joblib
import re
import requests
import os

# Load the trained model and label binarizer
model = joblib.load('model/phishing_model.pkl')
lb = joblib.load('model/label_binarizer.pkl')

# --- API Key ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "Your Key")

# --- Helper functions ---
def extract_urls(text):
    """Extract all URLs from the input text using regex."""
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

def keyword_suspicious(url):
    """Fallback: Basic keyword-based suspicious check."""
    suspicious_keywords = [
        'login', 'verify', 'update', 'secure',
        'bank', 'account', 'click', 'confirm'
    ]
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def check_url_virustotal(url):
    """Check if a URL is malicious using VirusTotal API, fallback to keyword check if fails."""
    if VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE" or not VIRUSTOTAL_API_KEY.strip():
        print("[!] No API key set — using keyword check.")
        return keyword_suspicious(url)

    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": url}

    try:
        resp = requests.post(api_url, headers=headers, data=data, timeout=10)
        if resp.status_code != 200:
            print(f"[!] VT API error ({resp.status_code}) — using keyword check.")
            return keyword_suspicious(url)

        analysis_id = resp.json()["data"]["id"]
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_resp = requests.get(report_url, headers=headers, timeout=10)

        if report_resp.status_code != 200:
            print(f"[!] VT report error ({report_resp.status_code}) — using keyword check.")
            return keyword_suspicious(url)

        stats = report_resp.json()["data"]["attributes"]["stats"]
        if stats.get("malicious", 0) > 0 or stats.get("phishing", 0) > 0:
            return True

        return False

    except Exception as e:
        print(f"[!] API check failed for {url}: {e}")
        return keyword_suspicious(url)

def final_prediction(email_text):
    # Step 1: ML Model prediction
    model_pred = lb.inverse_transform(model.predict([email_text]))[0]

    # Step 2: URL check
    urls = extract_urls(email_text)
    malicious_urls = [url for url in urls if check_url_virustotal(url)]

    # Step 3: Combine results
    if malicious_urls:
        return "Phishing (Malicious or Suspicious URL Detected)", malicious_urls
    else:
        return model_pred, urls

# --- Main Program ---
if __name__ == "__main__":
    print("\nPaste the email content below (type 'exit' to quit):\n")
    while True:
        email_input = input(">>> ")
        if email_input.lower() == "exit":
            break

        prediction, urls = final_prediction(email_input)
        print(f"\n📧 Prediction: {prediction}")
        if urls:
            print("🔗 URLs Found:")
            for url in urls:
                print("   -", url)
        else:
            print("🔗 No URLs found.")
        print("-" * 40)
