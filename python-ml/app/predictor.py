import os
import joblib
import pandas as pd
import numpy as np
from feature_extractor import extract_features

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(os.path.dirname(BASE_DIR), "model")

# Load Models
try:
    model = joblib.load(os.path.join(MODEL_DIR, "lgbm_model.pkl"))
    scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    selected_features = joblib.load(os.path.join(MODEL_DIR, "selected_features.pkl"))
except Exception as e:
    print(f"Error loading models: {e}")
    model = None
    scaler = None
    selected_features = []

# Trusted Domains Whitelist to prevent false positives on major sites
TRUSTED_DOMAINS = {
    'google.com', 'google.co.id', 'youtube.com', 'youtu.be', 'yahoo.com', 
    'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 
    'github.com', 'microsoft.com', 'apple.com', 'netflix.com', 
    'wikipedia.org', 'cloudflare.com', 'zoom.us', 'whatsapp.com', 
    'spotify.com', 'reddit.com', 'pinterest.com', 'amazon.com', 
    'tiktok.com', 'canva.com', 'githubusercontent.com', 'medium.com'
}

def predict(url: str) -> dict:
    """
    Extracts features from URL, scales them, and predicts phishing/safe.
    """
    if model is None or scaler is None:
        return {"error": "Model not loaded"}

    # 0. Check Whitelist
    try:
        import tldextract
        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}".lower()
        if registered_domain in TRUSTED_DOMAINS:
            return {
                "url": url,
                "label": 1, # Safe (Benign)
                "confidence": 100.0,
                "status": "safe",
                "features_used": ["URL is a trusted domain (whitelisted)"],
                "raw_features": {}
            }
    except Exception as e:
        print(f"Error checking whitelist: {e}")

    # 1. Extract features
    raw_features = extract_features(url)
    
    # 2. Arrange features in the correct order
    feature_values = []
    for feat in selected_features:
        feature_values.append(raw_features.get(feat, 0))
    
    # Convert to numeric (ensure no strings/None)
    feature_values = [float(v) if v is not None else 0.0 for v in feature_values]
    
    # Convert to DataFrame to match feature names and avoid scikit-learn warnings
    x_df = pd.DataFrame([feature_values], columns=selected_features)
    
    # 3. Scale features
    x_scaled = scaler.transform(x_df)
    
    # Convert scaled features back to DataFrame to preserve feature names for LightGBM
    x_scaled_df = pd.DataFrame(x_scaled, columns=selected_features)
    
    # 4. Predict
    # predict_proba for confidence
    probs = model.predict_proba(x_scaled_df)[0]
    label = int(np.argmax(probs)) # 0 = phishing, 1 = safe (original PhiUSIIL labels)
    confidence = float(np.max(probs))
    
    status = "safe" if label == 1 else "phishing"
    
    # Find top contributing features (approximate by looking at high values in scaled data)
    # Or just return the most 'suspicious' lexical features
    suspicious_features = []
    if label == 0:
        # Example of identifying features that contributed
        # For simplicity, we'll return some interesting ones
        if raw_features.get('NoOfOtherSpecialCharsInURL', 0) > 5:
            suspicious_features.append("High number of special characters in URL")
        if raw_features.get('IsHTTPS') == 0:
            suspicious_features.append("URL does not use HTTPS")
        if raw_features.get('URLLength', 0) > 100:
            suspicious_features.append("URL is unusually long")
        if raw_features.get('NoOfiFrame', 0) > 0:
            suspicious_features.append("URL contains hidden iframes")

    return {
        "url": url,
        "label": label,
        "confidence": round(confidence * 100, 2),
        "status": status,
        "features_used": suspicious_features if label == 0 else ["URL appears standard"],
        "raw_features": {k: raw_features[k] for k in selected_features[:10]} # Summary of top 10 features
    }
