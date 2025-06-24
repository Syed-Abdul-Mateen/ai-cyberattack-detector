# AI-Driven Real-Time Cyberattack Detection & Mitigation System

This project is a full-stack Python + Flask application that monitors real-time network packets, detects cyber threats, identifies root causes, blocks malicious IPs, visualizes attack paths, and generates PDF reports — all in real time.

---

## Features

- Real-time packet sniffing using Scapy
- Suspicious IP detection and root cause analysis
- Automatic IP blocking via Windows Firewall
- Graph-based attack path visualization with NetworkX and Matplotlib
- PDF report generation using ReportLab
- Email alert notifications
- Flask-based secure web dashboard with login system

---



## How to Run

This project runs best on Windows due to integration with Windows Firewall for IP blocking.

1. Create and activate a virtual environment:

python -m venv venv
venv\Scripts\activate



2. Install dependencies:

pip install -r requirements.txt


3. Run the application:

python app.py



4. Open your browser and visit:

http://127.0.0.1:5000


Use the login provided in `app.py` to access the dashboard.

---

## Developed By

**Syed Abdul Mateen**  
B.Tech (CSE), ICFAI University, Hyderabad  
GitHub: [https://github.com/Syed-Abdul-Mateen](https://github.com/Syed-Abdul-Mateen)

---

## License

This project is open for academic and learning purposes. Feel free to fork and enhance it.
