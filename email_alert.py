import smtplib
from email.message import EmailMessage

# === Your Email Configuration ===
EMAIL_SENDER = "abdulmateen22.dm@gmail.com"
EMAIL_PASSWORD = "sbxwjhpmzpkrnhsn"  # App password with no spaces
EMAIL_RECEIVER = "abdulmateen22.dm@gmail.com"  # You can change this

def send_email_alert(src, dst, root_cause):
    subject = f"🚨 Cyber Threat Detected from {src}"
    body = (
        f"A suspicious packet has been detected.\n\n"
        f"📍 Source IP: {src}\n"
        f"🎯 Destination IP: {dst}\n"
        f"🧠 Suspected Vulnerability: {root_cause}\n"
        f"⏱️ Time: Sent from your real-time monitoring dashboard\n\n"
        f"⚠️ Action Taken: The IP has been blocked, logged, and traced.\n\n"
        f"Regards,\n"
        f"Cyber Defense System"
    )

    # Build Email
    msg = EmailMessage()
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"✅ Email alert sent for {src}")
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")
