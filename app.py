from flask import Flask, render_template, request, jsonify
from detector import PhishingDetector
import os

app = Flask(__name__)
detector = PhishingDetector()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            return render_template('index.html', error="Please enter a URL")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            result = detector.predict_phishing(url)
            return render_template('index.html', result=result)
        except Exception as e:
            return render_template('index.html', error=f"Error analyzing URL: {str(e)}")
    
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        result = detector.predict_phishing(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(port=5001, debug=True)  # Try a different port