import pandas as pd
import numpy as np
import re
import urllib.parse
import socket
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

# Try to import whois with fallback
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

class PhishingDetector:
    def __init__(self):
        self.model, self.scaler = self.initialize_model()
    
    def initialize_model(self):
        # Load the provided dataset
        data = pd.read_csv('5.urldata (1).csv')

        # Prepare training data
        X = data.drop(['Domain', 'Label'], axis=1).values
        y = data['Label'].values

        # Add synthetic legitimate examples
        legit_patterns = [
            [0,0,20,1,0,1,0,0,1,1,1,1,0,0,0,0],  
            [0,0,25,2,0,1,0,0,1,1,1,1,0,0,0,0],  
            [0,0,30,1,0,1,0,0,1,1,1,1,0,0,0,0],  
            [0,0,35,2,0,1,0,0,1,1,1,1,0,0,0,0],  
            [0,0,40,1,0,1,0,0,1,1,1,1,0,0,0,0],  
            [0,0,50,2,0,1,0,0,1,1,1,1,0,0,0,0],  
            [0,0,45,1,0,1,0,0,1,1,1,1,0,0,0,0]   
        ]

        # Add more synthetic phishing examples
        phishing_patterns = [
            [1,0,30,3,1,0,1,1,0,0,0,0,1,1,1,1],  # Typical phishing
            [0,1,25,2,0,0,1,1,0,0,0,0,1,1,1,1],  # Uses @ symbol
            [0,0,15,1,0,0,1,1,0,0,0,0,1,1,1,1],  # Short URL
            [0,0,40,4,1,0,1,1,0,0,0,0,1,1,1,1],  # Deep path
            [1,0,50,2,0,0,1,1,0,0,0,0,1,1,1,1],  # Uses IP
            [0,0,30,2,0,0,1,1,0,0,0,0,1,1,1,1],  # Hyphen in domain
            [0,0,25,3,0,0,1,1,0,0,0,0,1,1,1,1]   # Suspicious combo
        ]

        X = np.vstack([X, legit_patterns, phishing_patterns])
        y = np.concatenate([y, np.zeros(len(legit_patterns)), np.ones(len(phishing_patterns))])

        # Split data for stacking
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Define base models
        estimators = [
            ('rf', RandomForestClassifier(
                n_estimators=150,
                max_depth=7,
                min_samples_split=5,
                class_weight='balanced',
                random_state=42
            )),
            ('gb', GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=4,
                random_state=42
            )),
            ('svm', SVC(
                kernel='rbf',
                C=1.0,
                gamma='scale',
                probability=True,
                random_state=42
            ))
        ]

        # Define meta-learner
        meta_learner = LogisticRegression(
            class_weight='balanced',
            random_state=42,
            max_iter=1000
        )

        # Create stacking classifier
        model = StackingClassifier(
            estimators=estimators,
            final_estimator=meta_learner,
            stack_method='predict_proba',
            passthrough=True,
            cv=5
        )

        # Train the model
        model.fit(X_train, y_train)

        scaler = StandardScaler()
        scaler.fit(X)

        return model, scaler

    def extract_features(self, url):
        features = {}
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()

        # Enhanced well-known domains list
        well_known_base_domains = [
            'google.com', 'github.com', 'amazon.com', 'facebook.com',
            'microsoft.com', 'twitter.com', 'apple.com', 'youtube.com',
            'linkedin.com', 'instagram.com', 'netflix.com', 'wikipedia.org',
            'paypal.com', 'gmail.com', 'outlook.com', 'yahoo.com',
            'research.google.com', 'drive.google.com', 'docs.google.com',
            'sites.google.com', 'colab.research.google.com'
        ]

        # Strict well-known domain check
        features['Well_Known'] = 0
        base_domain = '.'.join(domain.split('.')[-2:])
        for known_domain in well_known_base_domains:
            if domain == known_domain or domain.endswith('.' + known_domain):
                features['Well_Known'] = 1
                break

        # Domain features
        features['Have_IP'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
        features['Have_At'] = 1 if '@' in url else 0

        # URL structure
        features['URL_Length'] = len(url)
        features['URL_Depth'] = parsed.path.count('/')
        features['Redirection'] = 1 if '//' in url[7:] else 0
        features['https_Domain'] = 1 if parsed.scheme == 'https' else 0

        # Adjusted TinyURL logic
        features['TinyURL'] = 1 if len(url) < 22 and not features['Well_Known'] else 0

        # Enhanced prefix/suffix detection
        features['Prefix/Suffix'] = 1 if '-' in domain and not features['Well_Known'] else 0

        # Domain reputation
        features['DNS_Record'] = 0
        features['Domain_Age'] = 0
        features['Domain_End'] = 0

        if WHOIS_AVAILABLE and not features['Well_Known']:
            try:
                domain_info = whois.whois(domain)
                features['DNS_Record'] = 1 if domain_info else 0

                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                features['Domain_Age'] = 1 if creation_date and (datetime.now().date() - creation_date.date()).days > 365 else 0

                expiration_date = domain_info.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                features['Domain_End'] = 1 if expiration_date and expiration_date.date() > datetime.now().date() else 0
            except:
                pass

        # Other features
        features['Web_Traffic'] = features['Well_Known']
        features['iFrame'] = 0
        features['Mouse_Over'] = 0
        features['Right_Click'] = 0 if features['Well_Known'] else 1
        features['Web_Forwards'] = features['Redirection']

        return features

    def predict_phishing(self, url):
        features = self.extract_features(url)

        feature_order = [
            'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
            'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
            'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame',
            'Mouse_Over', 'Right_Click', 'Web_Forwards'
        ]

        feature_values = [features[col] for col in feature_order]
        features_scaled = self.scaler.transform([feature_values])

        pred = self.model.predict(features_scaled)[0]
        proba = self.model.predict_proba(features_scaled)[0][1]

        # Probability adjustment
        if features['Well_Known']:
            proba_adjusted = max(0.01, float(proba) * 0.01)  # Very strong reduction for well-known
        else:
            suspicious_features = sum(features[col] for col in ['Have_IP', 'Have_At', 'Prefix/Suffix', 'TinyURL'])
            proba_adjusted = min(0.99, float(proba) * (1 + suspicious_features * 0.5))

            # Additional boost for suspicious patterns
            if features['Prefix/Suffix'] and 'paypal' in url.lower() or 'bank' in url.lower():
                proba_adjusted = min(0.99, proba_adjusted * 1.8)

        # Final prediction logic
        if features['Well_Known']:
            final_pred = 'LEGITIMATE'
        elif proba_adjusted > 0.65 or ('paypal' in url.lower() and features['Prefix/Suffix']):
            final_pred = 'PHISHING'
        elif proba_adjusted > 0.4:
            final_pred = 'SUSPICIOUS'
        else:
            final_pred = 'LEGITIMATE'

        return {
            'url': url,
            'prediction': final_pred,
            'phishing_probability': proba_adjusted,
            'features': features
        }