from flask import Flask, render_template, request
from osint_sources import generate_google_dorks, analyze_email, analyze_phone, search_open_sanctions, search_shodan
import socket
import os

app = Flask(__name__)

OPEN_SANCTIONS_API_KEY = os.getenv("OPEN_SANCTIONS_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

@app.route('/', methods=['GET', 'POST'])
def index():
    results = {}
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        if name or email or phone:
            results['google_dorks'] = generate_google_dorks(name, email, phone)

        if email:
            results['email_analysis'] = analyze_email(email)
            if SHODAN_API_KEY:
                try:
                    domain = email.split('@')[1]
                    ip_address = socket.gethostbyname(domain)
                    results['shodan'] = search_shodan(ip_address, SHODAN_API_KEY)
                except socket.gaierror:
                    print(f"Could not resolve domain: {domain}")

        if phone:
            results['phone_analysis'] = analyze_phone(phone)

        if name and OPEN_SANCTIONS_API_KEY:
            results['open_sanctions'] = search_open_sanctions(name, OPEN_SANCTIONS_API_KEY)

    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
