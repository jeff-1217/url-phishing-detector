from flask import Flask, render_template, request
import requests, os
from lexical import lexical_score
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
GSB_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        # Lexical analysis
        lex = lexical_score(url)

        # Safe Browsing check
        payload = {
            'client': {'clientId': 'yourApp', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        params = {'key': API_KEY}
        resp = requests.post(GSB_URL, json=payload, params=params)
        data = resp.json()
        safe = 'matches' not in data

        result = {
            'url': url,
            'lexical': lex,
            'safe_browsing': safe,
            'threat_matches': data.get('matches', [])
        }
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)