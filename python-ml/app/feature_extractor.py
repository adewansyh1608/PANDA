import re
import tldextract
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

def extract_features(url: str) -> dict:
    """
    Extracts 54 lexical and content features from a URL (subsetted to 40 for the model).
    Based on PhiUSIIL Phishing URL Dataset features.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    features = {}
    
    # 1. Lexical Features
    try:
        parsed_url = urlparse(url)
        tld_ext = tldextract.extract(url)
        
        domain = tld_ext.domain + '.' + tld_ext.suffix
        path = parsed_url.path
        
        features['URLLength'] = len(url)
        features['DomainLength'] = len(domain)
        features['TLDLength'] = len(tld_ext.suffix)
        
        # Letters and Digits
        letters = [c for c in url if c.isalpha()]
        digits = [c for c in url if c.isdigit()]
        features['NoOfLettersInURL'] = len(letters)
        features['LetterRatioInURL'] = len(letters) / len(url) if len(url) > 0 else 0
        features['NoOfDegitsInURL'] = len(digits)
        features['DegitRatioInURL'] = len(digits) / len(url) if len(url) > 0 else 0
        
        # Special Characters
        features['NoOfEqualsInURL'] = url.count('=')
        features['NoOfQMarkInURL'] = url.count('?')
        
        # Other special chars (non-alphanumeric, excluding some common ones)
        # In PhiUSIIL, 'OtherSpecialChars' usually means chars like @, _, -, etc.
        special_chars = re.sub(r'[a-zA-Z0-9]', '', url)
        features['NoOfOtherSpecialCharsInURL'] = len(special_chars)
        features['SpacialCharRatioInURL'] = len(special_chars) / len(url) if len(url) > 0 else 0
        
        features['IsHTTPS'] = 1 if parsed_url.scheme == 'https' else 0
        
        # Char Continuation Rate (Heuristic: max sequence of same type)
        # Simplified: ratio of longest repeating character
        if len(url) > 0:
            max_repeat = 1
            current_repeat = 1
            for i in range(1, len(url)):
                if url[i] == url[i-1]:
                    current_repeat += 1
                else:
                    max_repeat = max(max_repeat, current_repeat)
                    current_repeat = 1
            max_repeat = max(max_repeat, current_repeat)
            features['CharContinuationRate'] = max_repeat / len(url)
        else:
            features['CharContinuationRate'] = 0

        # Probabilities & Similarity (Requires reference data we don't have)
        # Setting heuristics for demonstration
        features['URLSimilarityIndex'] = 100.0 # Placeholder
        features['TLDLegitimateProb'] = 0.52 # Placeholder (Average)
        features['URLCharProb'] = 0.05 # Placeholder

    except Exception:
        # Fallback for invalid URLs
        features['URLLength'] = len(url)
        features['DomainLength'] = 0
        features['TLDLength'] = 0
        features['NoOfLettersInURL'] = 0
        features['LetterRatioInURL'] = 0
        features['NoOfDegitsInURL'] = 0
        features['DegitRatioInURL'] = 0
        features['NoOfEqualsInURL'] = 0
        features['NoOfQMarkInURL'] = 0
        features['NoOfOtherSpecialCharsInURL'] = 0
        features['SpacialCharRatioInURL'] = 0
        features['IsHTTPS'] = 0
        features['CharContinuationRate'] = 0
        features['URLSimilarityIndex'] = 0
        features['TLDLegitimateProb'] = 0
        features['URLCharProb'] = 0

    # 2. Page-Content Features (Requires Request)
    # Defaulting all to 0/False
    content_features = [
        'LineOfCode', 'HasTitle', 'DomainTitleMatchScore', 'URLTitleMatchScore',
        'HasFavicon', 'Robots', 'IsResponsive', 'NoOfSelfRedirect', 'HasDescription',
        'NoOfiFrame', 'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton',
        'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto',
        'HasCopyrightInfo', 'NoOfImage', 'NoOfJS', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
    ]
    for feat in content_features:
        features[feat] = 0

    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code == 200:
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            
            features['LineOfCode'] = len(html.splitlines())
            
            title = soup.title.string if soup.title else ""
            features['HasTitle'] = 1 if title else 0
            
            if title:
                # Simple match score
                domain_name = tld_ext.domain.lower()
                title_lower = title.lower()
                features['DomainTitleMatchScore'] = 100 if domain_name in title_lower else 0
                features['URLTitleMatchScore'] = 100 if title_lower in url.lower() else 0
            
            features['HasFavicon'] = 1 if (soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')) else 0
            features['HasDescription'] = 1 if soup.find('meta', attrs={'name': 'description'}) else 0
            features['NoOfiFrame'] = len(soup.find_all('iframe'))
            features['NoOfImage'] = len(soup.find_all('img'))
            features['NoOfJS'] = len(soup.find_all('script'))
            
            # Form submits
            forms = soup.find_all('form')
            features['HasSubmitButton'] = 1 if soup.find_all('button', type='submit') or soup.find_all('input', type='submit') else 0
            features['HasPasswordField'] = 1 if soup.find_all('input', type='password') else 0
            features['HasHiddenFields'] = 1 if soup.find_all('input', type='hidden') else 0
            
            # External form submit
            ext_form = 0
            for form in forms:
                action = form.get('action', '')
                if action.startswith('http') and domain not in action:
                    ext_form = 1
                    break
            features['HasExternalFormSubmit'] = ext_form
            
            # Keywords
            content_lower = html.lower()
            features['Bank'] = 1 if any(kw in content_lower for kw in ['bank', 'login', 'secure', 'account']) else 0
            features['Pay'] = 1 if any(kw in content_lower for kw in ['pay', 'paypal', 'card', 'visa', 'mastercard']) else 0
            features['Crypto'] = 1 if any(kw in content_lower for kw in ['crypto', 'wallet', 'bitcoin', 'eth']) else 0
            
            # Links
            all_links = soup.find_all('a', href=True)
            self_ref = 0
            empty_ref = 0
            ext_ref = 0
            for link in all_links:
                href = link['href']
                if href == '#' or href == '' or 'javascript:void(0)' in href:
                    empty_ref += 1
                elif href.startswith('/') or domain in href:
                    self_ref += 1
                else:
                    ext_ref += 1
            features['NoOfSelfRef'] = self_ref
            features['NoOfEmptyRef'] = empty_ref
            features['NoOfExternalRef'] = ext_ref
            features['HasCopyrightInfo'] = 1 if 'copyright' in content_lower or '©' in html else 0

    except Exception:
        pass # Keep defaults
    
    return features
