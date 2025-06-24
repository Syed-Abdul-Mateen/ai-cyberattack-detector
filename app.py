from flask import Flask, render_template, jsonify, send_from_directory, request, redirect, session, url_for
from monitor import run_sniffer_in_background, stop_sniffing, detected_logs, attack_counts
from pdf_report import generate_pdf_report
import os

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'  # Needed for session

# === AUTH ===
USERNAME = "admin"
PASSWORD = "1234"  # Change this to something secure

# === Routes ===

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == USERNAME and request.form['password'] == PASSWORD:
            session['logged_in'] = True
            return redirect('/')
        else:
            return render_template('login.html', error="Invalid username or password")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect('/login')

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect('/login')
    return render_template('index.html')

@app.route('/start')
def start():
    run_sniffer_in_background()
    return "Sniffer started"

@app.route('/stop')
def stop():
    stop_sniffing()
    return "Sniffer stopped"

@app.route('/logs')
def logs():
    return jsonify(detected_logs)

@app.route('/chart-data')
def chart_data():
    sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
    top_ips = [ip for ip, count in sorted_attacks[:5]]
    counts = [count for ip, count in sorted_attacks[:5]]
    return jsonify({"labels": top_ips, "data": counts})

@app.route('/download-graph')
def download_graph():
    return send_from_directory('static', 'graph.png', as_attachment=True)

@app.route('/generate-report')
def generate_report():
    generate_pdf_report()
    return send_from_directory('logs', 'Attack_Report.pdf', as_attachment=True)

@app.route('/clear')
def clear_logs_and_graph():
    detected_logs.clear()
    attack_counts.clear()
    with open("logs/detected_logs.txt", "w") as f:
        f.write("")
    with open("logs/root_cause_report.txt", "w") as f:
        f.write("")
    from attack_graph import clear_graph
    clear_graph()
    return "Cleared all logs and graph"

if __name__ == '__main__':
    app.run(debug=True)
