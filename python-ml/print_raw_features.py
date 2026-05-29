import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app"))

from feature_extractor import extract_features

print("Google.com raw features:")
g_feats = extract_features("https://www.google.com")
for k, v in sorted(g_feats.items()):
    print(f"  {k}: {v}")

print("-" * 50)
print("Github.com raw features:")
git_feats = extract_features("https://github.com")
for k, v in sorted(git_feats.items()):
    print(f"  {k}: {v}")
