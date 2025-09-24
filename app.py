# app.py
import os
from datetime import datetime, timedelta
import secrets, hashlib

from flask import Flask, render_template, request, redirect, session, flash, url_for
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, OTP
from email_utils import send_email

load_dotenv()  # loads .env

def create_app():
    app = Flask(__name__, template_folder="templates")
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    return app

app = create_app()

OTP_EXPIRY = int(os.getenv('OTP_EXPIRY_SECONDS', 300))
MAX_ATTEMPTS = int(os.getenv('MAX_OTP_ATTEMPTS', 5))

@app.route("/")
def index():
    if session.get('user_id'):
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username").strip()
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        if not username or not email or not password:
            flash("Fill all fields", "warning")
            return render_template("register.html")

        # check duplicates
        if User.query.filter((User.username==username)|(User.email==email)).first():
            flash("Username or email already exists", "danger")
            return render_template("register.html")

        user = User(username=username, email=email, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash("Registered. Please login.", "success")
        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password", "danger")
            return render_template("login.html")
        # Generate OTP
        otp_plain = f"{secrets.randbelow(900000) + 100000}"  # 6-digit
        otp_hash = hashlib.sha256(otp_plain.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(seconds=OTP_EXPIRY)
        otp_row = OTP(user_id=user.id, otp_hash=otp_hash, expires_at=expires_at)
        db.session.add(otp_row)
        db.session.commit()

        # send email (prints to console if mail not configured)
        subject = "Your login OTP"
        body = f"Hello {user.username},\n\nYour OTP is: {otp_plain}\nIt will expire in {OTP_EXPIRY//60} minutes.\n\nIf you didn't request this, ignore."
        send_email(user.email, subject, body)

        # save a pending user id in session until OTP verified
        session['pending_user_id'] = user.id
        flash("OTP sent to your email (or printed to console).", "info")
        return redirect("/verify")
    return render_template("login.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    pending_id = session.get('pending_user_id')
    if not pending_id:
        flash("Start login first.", "warning")
        return redirect("/login")

    if request.method == "POST":
        submitted = request.form.get("otp").strip()
        if not submitted:
            flash("Enter OTP", "warning")
            return render_template("varify.html")

        otp_row = OTP.query.filter_by(user_id=pending_id, used=False).order_by(OTP.created_at.desc()).first()
        if not otp_row:
            flash("No OTP found, request login again.", "danger")
            return redirect("/login")
        if datetime.utcnow() > otp_row.expires_at:
            flash("OTP expired. Please login again.", "danger")
            return redirect("/login")
        if otp_row.attempts >= MAX_ATTEMPTS:
            flash("Too many wrong attempts. Please login again.", "danger")
            return redirect("/login")

        submitted_hash = hashlib.sha256(submitted.encode()).hexdigest()
        if submitted_hash == otp_row.otp_hash:
            otp_row.used = True
            db.session.commit()
            session.pop('pending_user_id', None)
            session['user_id'] = pending_id
            flash("Login successful!", "success")
            return redirect("/dashboard")
        else:
            otp_row.attempts += 1
            db.session.commit()
            flash("Wrong OTP. Try again.", "danger")
            return render_template("varify.html")
    return render_template("varify.html")

@app.route("/dashboard")
def dashboard():
    uid = session.get('user_id')
    if not uid:
        flash("Login first.", "warning")
        return redirect("/login")
    user = User.query.get(uid)
    return render_template("dashboard.html", username=user.username)

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash("Logged out.", "info")
    return redirect("/login")

if __name__ == "__main__":
    # simple dev server
    app.run(debug=True)
