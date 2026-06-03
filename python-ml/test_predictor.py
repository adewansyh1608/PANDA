import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app"))

import joblib
import numpy as np
from feature_extractor import extract_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "model")

model = joblib.load(os.path.join(MODEL_DIR, "lgbm_model.pkl"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
selected_features = joblib.load(os.path.join(MODEL_DIR, "selected_features.pkl"))

def test_url(url):
    print(f"=== Testing URL: {url} ===")
    raw_features = extract_features(url)
    
    feature_values = []
    for feat in selected_features:
        feature_values.append(raw_features.get(feat, 0))
    feature_values = [float(v) if v is not None else 0.0 for v in feature_values]
    
    import pandas as pd
    x_df = pd.DataFrame([feature_values], columns=selected_features)
    x_scaled = scaler.transform(x_df)
    x_scaled_df = pd.DataFrame(x_scaled, columns=selected_features)
    
    probs = model.predict_proba(x_scaled_df)[0]
    print(f"Probabilities: Phishing (0): {probs[0]:.4f}, Benign (Safe, 1): {probs[1]:.4f}")
    
    # Print the top 5 scaled features to inspect what might be causing the classification
    scaled_dict = x_scaled_df.iloc[0].to_dict()
    sorted_scaled = sorted(scaled_dict.items(), key=lambda item: abs(item[1]), reverse=True)
    print("Top 5 highest absolute scaled features:")
    for k, v in sorted_scaled[:5]:
        print(f"  {k}: scaled={v:.4f}, raw={raw_features.get(k)}")
    print("-" * 50)

test_url("https://www.google.com")
test_url("http://phishing-test-site.com")
test_url("https://github.com")
test_url("https://youtu.be/xj3xEisC7D4?si=5Q0boj_kHQzqDwxI")
