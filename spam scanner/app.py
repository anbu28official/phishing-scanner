import numpy as np
import pandas as pd
import json
import re
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse

app = Flask(__name__)

# --- 1. CONFIGURATION ---
# We define the exact order of features here to ensure the AI doesn't get confused
FEATURE_ORDER = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", 
    "PrefixSuffix-", "SubDomains", "HTTPS", "HTTPSDomainURL", "NonStdPort",
    "AnchorURL", "IframeRedirection", "ServerFormHandler", "StatusBarCust", "DisableRightClick"
]

# --- 2. HTML SCANNER (PARANOID MODE) ---
def extract_html_features(url):
    # Default: Assume SUSPICIOUS (-1) if we can't verify the site
    # 1 = Safe, -1 = Phishing, 0 = Suspicious
    features = {
        "AnchorURL": -1, 
        "IframeRedirection": -1, 
        "ServerFormHandler": -1, 
        "StatusBarCust": -1, 
        "DisableRightClick": -1
    }
    
    try:
        # Timeout is 3 seconds. If site is slow, we assume it's hiding something.
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, timeout=3, headers=headers)
        
        # If we get here, the site is LIVE. Now we can judge it fairly.
        # Reset defaults to Safe (1) and then look for bad things.
        features = {k: 1 for k in features} 
        
        soup = BeautifulSoup(response.text, 'html.parser')
        domain = urlparse(url).netloc

        # --- BAD THING 1: IFrames ---
        if soup.find_all('iframe', width=0) or soup.find_all('iframe', style=re.compile(r'display:\s*none')):
            features['IframeRedirection'] = -1

        # --- BAD THING 2: Right Click Disabled ---
        if soup.find_all('script', text=re.compile(r'event\.button\s*==\s*2')):
            features['DisableRightClick'] = -1

        # --- BAD THING 3: Fake Status Bar ---
        if soup.find_all('script', text=re.compile(r'window\.status')):
            features['StatusBarCust'] = -1

        # --- BAD THING 4: Anchors pointing elsewhere ---
        anchors = soup.find_all('a', href=True)
        unsafe = 0
        total = len(anchors)
        if total > 0:
            for tag in anchors:
                href = tag['href']
                if href.startswith(('http', 'https')) and domain not in href:
                    unsafe += 1
            percentage = unsafe / total
            if percentage > 0.6: # If >60% of links go to other sites
                features['AnchorURL'] = -1
            elif percentage > 0.3:
                features['AnchorURL'] = 0

        # --- BAD THING 5: Forms submitting to blank/external ---
        forms = soup.find_all('form', action=True)
        for form in forms:
            action = form['action']
            if action == "" or action == "about:blank":
                features['ServerFormHandler'] = -1
            elif action.startswith(('http', 'https')) and domain not in action:
                features['ServerFormHandler'] = 0

    except Exception as e:
        print(f"⚠️ Could not reach site: {e}")
        print("   -> Assuming HTML features are MALICIOUS (-1) due to connection failure.")
        # We keep the default -1 values set at the top
        pass
    
    return features

# --- 3. URL FEATURE ENGINE ---
def get_features(url):
    f = []
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. UsingIP
    f.append(-1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 1)
    
    # 2. LongURL
    length = len(url)
    f.append(-1 if length > 75 else (0 if length > 54 else 1))
    
    # 3. ShortURL
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co']
    f.append(-1 if any(s in domain for s in shorteners) else 1)
    
    # 4. Symbol@
    f.append(-1 if '@' in url else 1)
    
    # 5. Redirecting//
    f.append(-1 if url.rfind('//') > 7 else 1)
    
    # 6. PrefixSuffix-
    f.append(-1 if '-' in domain else 1)
    
    # 7. SubDomains
    dots = domain.replace('www.', '').count('.')
    f.append(-1 if dots > 2 else (0 if dots == 2 else 1))
    
    # 8. HTTPS
    f.append(1 if parsed.scheme == 'https' else -1)
    
    # 9. HTTPSDomainURL (Fake https in name)
    f.append(-1 if 'https' in domain and parsed.scheme != 'https' else 1)
    
    # 10. NonStdPort
    f.append(-1 if parsed.port and parsed.port not in [80, 443] else 1)
    
    # --- HTML FEATURES ---
    html_f = extract_html_features(url)
    
    # CRITICAL: Add them in the exact order of FEATURE_ORDER
    f.append(html_f['AnchorURL'])
    f.append(html_f['IframeRedirection'])
    f.append(html_f['ServerFormHandler'])
    f.append(html_f['StatusBarCust'])
    f.append(html_f['DisableRightClick'])
    
    return f

# --- 4. TRAIN MODEL ---
print("⚡ Training AI Model...")
try:
    df = pd.read_csv('phishing.csv')
    
    # Filter dataset to only the 15 columns we use
    X = df[FEATURE_ORDER]
    y = df['class']
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    print("✅ Model Trained!")
except Exception as e:
    print(f"❌ Error loading dataset: {e}")
    exit()

# --- 5. SERVER ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    print(f"\n🔍 SCANNING: {url}")
    
    features = [get_features(url)]
    
    # --- DEBUGGING PRINT ---
    # This will show you exactly what the AI sees in your terminal
    print(f"📊 Extracted Features: {features[0]}")
    # (-1 = Bad, 1 = Good)
    
    prediction = model.predict(features)[0]
    prob = model.predict_proba(features)[0]
    
    # Dataset: 1 = Safe, -1 = Phishing
    safe_idx = list(model.classes_).index(1)
    phish_idx = list(model.classes_).index(-1)
    
    safe_score = prob[safe_idx] * 100
    phish_score = prob[phish_idx] * 100
    
    print(f"🧠 AI Verdict: Safe={safe_score:.1f}% | Malicious={phish_score:.1f}%")
    
    if prediction == 1:
        result = "SAFE"
        confidence = round(safe_score, 2)
    else:
        result = "MALICIOUS"
        confidence = round(phish_score, 2)

    return jsonify({
        'url': url,
        'result': result,
        'confidence': confidence
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)