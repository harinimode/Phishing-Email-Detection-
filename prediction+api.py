import joblib
import re
import requests

# ✅ Hardcoded Google API Key (use with caution)
API_KEY = "AIzaSyCOk0o1_VxTEI_Ob1varuoB-XeJ6XL7DCQ"

# Load model and label binarizer
model = joblib.load('model/phishing_model.pkl')
lb = joblib.load('model/label_binarizer.pkl')

def extract_urls(text):
    """Extract all URLs from the input text using regex."""
    url_pattern = r'((https?:\/\/)?([\w\-]+\.)+[a-zA-Z]{2,}(/[^\s]*)?)'
    return [match[0] for match in re.findall(url_pattern, text)]

def is_url_suspicious_heuristic(url):
    """Check URL using simple suspicious keyword heuristics."""
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'click', 'confirm']
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def check_google_safe_browsing(url):
    """Check if the URL is flagged by Google's Safe Browsing API."""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        if response.status_code == 200:
            return bool(response.json().get("matches"))
        else:
            print(f"⚠️ Google API error: {response.status_code}")
            return False
    except Exception as e:
        print(f"⚠️ Exception while calling Google API: {e}")
        return False

def final_prediction(email_text):
    model_pred = lb.inverse_transform(model.predict([email_text]))[0]
    urls = extract_urls(email_text)
    flagged_urls = []

    for url in urls:
        heuristic_flag = is_url_suspicious_heuristic(url)
        google_flag = check_google_safe_browsing(url)
        if heuristic_flag or google_flag:
            flagged_urls.append((url, "Suspicious" if heuristic_flag else "Flagged by Google"))

    if flagged_urls:
        return "Phishing (Suspicious URL Detected)", flagged_urls
    else:
        return model_pred, urls

if __name__ == "__main__":
    print("\n📧 Paste the email content below (type 'exit' to quit):\n")
    while True:
        email_input = input(">>> ")
        if email_input.lower() == "exit":
            break

        prediction, urls_info = final_prediction(email_input)
        print(f"\n📌 Prediction: {prediction}")
        if urls_info:
            print("🔗 URLs Found:")
            for item in urls_info:
                if isinstance(item, tuple):
                    print(f"   - {item[0]} ❗ ({item[1]})")
                else:
                    print(f"   - {item}")
        else:
            print("🔗 No URLs found.")
        print("-" * 40)

'''import joblib
import re
import requests

# Load the trained model and label binarizer
model = joblib.load('model/phishing_model.pkl')
lb = joblib.load('model/label_binarizer.pkl')

# Your Google API Key (replace with your own) // API--> AIzaSyCymBgCqi8wPYpO33Tm4UuFatQTJmq6W9E
GOOGLE_API_KEY = "AIzaSyCymBgCqi8wPYpO33Tm4UuFatQTJmq6W9E"
SAFE_BROWSING_API = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

# --- Helper functions ---
def extract_urls(text):
    url_pattern = r'((https?:\/\/)?([\w\-]+\.)+[a-zA-Z]{2,}(/[^\s]*)?)'
    return [match[0] for match in re.findall(url_pattern, text)]


def is_url_suspicious_heuristic(url):
    """Basic keyword check to flag suspicious URLs."""
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'click', 'confirm']
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def check_url_google_safe_browsing(url):
    """Check a URL using Google Safe Browsing API."""
    payload = {
        "client": {
            "clientId": "your-app-name",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(SAFE_BROWSING_API, json=payload)
        result = response.json()
        return bool(result.get("matches"))
    except Exception as e:
        print("⚠️ Safe Browsing API error:", e)
        return False

def final_prediction(email_text):
    # Step 1: ML Model prediction
    model_pred = lb.inverse_transform(model.predict([email_text]))[0]

    # Step 2: URL check (heuristic + Safe Browsing)
    urls = extract_urls(email_text)
    flagged_urls = []

    for url in urls:
        if is_url_suspicious_heuristic(url) or check_url_google_safe_browsing(url):
            flagged_urls.append(url)

    # Step 3: Combine both results
    if flagged_urls:
        return "Phishing (Suspicious URL Detected)", flagged_urls
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
'''