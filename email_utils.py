# email_utils.py
import os
import smtplib
from email.mime.text import MIMEText

MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

def send_email(to_email: str, subject: str, body: str):
    """Tries to send email via SMTP; if mail config missing, prints to console (for dev)."""
    if not MAIL_USERNAME or not MAIL_PASSWORD or not MAIL_SERVER:
        print("=== EMAIL (DEV) ===")
        print(f"To: {to_email}\nSubject: {subject}\n\n{body}")
        print("===================")
        return True

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = MAIL_USERNAME
    msg['To'] = to_email

    try:
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Failed to send email:", e)
        return False
