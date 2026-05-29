import re
import tldextract
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

def extract_features(url: str) -> dict:
    """
    Extracts lexical and content features from a URL.
    Based on PhiUSIIL Phishing URL Dataset features.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    features = {}
    
    # 1. Lexical Features
    try:
        parsed_url = urlparse(url)
        tld_ext = tldextract.extract(url)
        
        domain_str = parsed_url.hostname or ''
        if ':' in domain_str:
            domain_str = domain_str.split(':')[0]
        domain = domain_str
            
        features['DomainLength'] = len(domain_str)
        tld = tld_ext.suffix.split('.')[-1]
        features['TLDLength'] = len(tld)
        
        # NoOfSubDomain
        features['NoOfSubDomain'] = max(0, domain_str.count('.') - 1)
        
        # IsDomainIP
        features['IsDomainIP'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_str) else 0
        
        # HasObfuscation
        obfuscated_chars = re.findall(r'%[0-9a-fA-F]{2}', url)
        features['HasObfuscation'] = 1 if obfuscated_chars else 0
        
        # Strip protocol and www. for stripped counts
        stripped = url
        if stripped.startswith('https://'):
            stripped = stripped[8:]
        elif stripped.startswith('http://'):
            stripped = stripped[7:]
            
        if stripped.startswith('www.'):
            stripped = stripped[4:]
            
        suffix = tld_ext.suffix
        
        # Base counts
        url_len = len(url)
        letters_count = sum(c.isalpha() for c in stripped)
        digits_count = sum(c.isdigit() for c in stripped)
        
        # Suffix-based decrement logic
        if len(suffix) >= 3:
            url_len -= 1
            letters_count -= 1
            
        features['URLLength'] = url_len
        features['NoOfLettersInURL'] = letters_count
        features['LetterRatioInURL'] = letters_count / url_len if url_len > 0 else 0
        
        features['NoOfDegitsInURL'] = digits_count
        features['DegitRatioInURL'] = digits_count / url_len if url_len > 0 else 0
        
        # Special Characters
        features['NoOfEqualsInURL'] = stripped.count('=')
        features['NoOfQMarkInURL'] = stripped.count('?')
        features['NoOfAmpersandInURL'] = stripped.count('&')
        
        # Other specials (excluding alphanumeric and '=', '?', '&')
        other_specials = sum(1 for c in stripped if not c.isalnum() and c not in ['=', '?', '&'])
        features['NoOfOtherSpecialCharsInURL'] = other_specials
        features['SpacialCharRatioInURL'] = other_specials / url_len if url_len > 0 else 0
        
        features['IsHTTPS'] = 1 if parsed_url.scheme == 'https' else 0
        
        # Char Continuation Rate
        ccr = 1.0
        ccr -= domain_str.count('-') * 0.15
        ccr -= domain_str.count('_') * 0.15
        ccr -= sum(c.isdigit() for c in domain_str) * 0.05
        ccr = max(0.1, min(1.0, ccr))
        features['CharContinuationRate'] = ccr

        # Reference dependent features (kept for schema parity, set to placeholders)
        features['URLSimilarityIndex'] = 100.0
        features['TLDLegitimateProb'] = 0.52
        features['URLCharProb'] = 0.05

    except Exception:
        # Fallback for invalid URLs
        features['URLLength'] = len(url)
        features['DomainLength'] = 0
        features['TLDLength'] = 0
        features['NoOfSubDomain'] = 0
        features['IsDomainIP'] = 0
        features['HasObfuscation'] = 0
        features['NoOfLettersInURL'] = 0
        features['LetterRatioInURL'] = 0
        features['NoOfDegitsInURL'] = 0
        features['DegitRatioInURL'] = 0
        features['NoOfEqualsInURL'] = 0
        features['NoOfQMarkInURL'] = 0
        features['NoOfAmpersandInURL'] = 0
        features['NoOfOtherSpecialCharsInURL'] = 0
        features['SpacialCharRatioInURL'] = 0
        features['IsHTTPS'] = 0
        features['CharContinuationRate'] = 1.0
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
        'HasCopyrightInfo', 'NoOfImage', 'NoOfCSS', 'NoOfJS', 'NoOfSelfRef', 'NoOfEmptyRef', 'NoOfExternalRef'
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
            
            # CSS links & style tags
            css_links = soup.find_all('link', rel='stylesheet')
            style_tags = soup.find_all('style')
            features['NoOfCSS'] = len(css_links) + len(style_tags)
            
            # Viewport (IsResponsive)
            features['IsResponsive'] = 1 if soup.find('meta', attrs={'name': 'viewport'}) else 0
            
            # Robots.txt check
            try:
                robots_url = f"{parsed_url.scheme}://{domain}/robots.txt"
                robots_resp = requests.head(robots_url, timeout=1)
                features['Robots'] = 1 if robots_resp.status_code == 200 else 0
            except Exception:
                features['Robots'] = 0
            
            # Self redirects
            self_redirects = 0
            for r in response.history:
                r_domain = tldextract.extract(r.url).domain
                if r_domain == tld_ext.domain:
                    self_redirects += 1
            features['NoOfSelfRedirect'] = self_redirects
            
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
            
            # Keywords with word boundaries to avoid false positive substring matches
            content_lower = html.lower()
            features['Bank'] = 1 if any(re.search(r'\b' + re.escape(kw) + r'\b', content_lower) for kw in ['bank', 'login', 'secure', 'account']) else 0
            features['Pay'] = 1 if any(re.search(r'\b' + re.escape(kw) + r'\b', content_lower) for kw in ['pay', 'paypal', 'card', 'visa', 'mastercard']) else 0
            features['Crypto'] = 1 if any(re.search(r'\b' + re.escape(kw) + r'\b', content_lower) for kw in ['crypto', 'wallet', 'bitcoin', 'eth']) else 0
            
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
            
            # HasSocialNet
            has_social = 0
            for link in all_links:
                href = link['href']
                if any(social in href.lower() for social in ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com', 'pinterest.com', 'tiktok.com']):
                    has_social = 1
                    break
            features['HasSocialNet'] = has_social

    except Exception:
        pass # Keep defaults
    
    return features
