import os
import random
import string
import smtplib
import numpy as np
from datetime import datetime
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import cv2
import face_recognition
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret")

# MongoDB connection
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/voting_system")
mongo = PyMongo(app)

# Email config
EMAIL_SENDER = os.getenv("milliebwari@gmail.com")
EMAIL_PASSWORD = os.getenv("aytl kmyh ksxv fliw")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Upload folder
UPLOAD_FOLDER = 'static/face_images'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Helper: OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(receiver_email, otp):
    try:
        msg = MIMEText(f'Your OTP is: {otp}')
        msg['Subject'] = 'Voting System Verification'
        msg['From'] = EMAIL_SENDER
        msg['To'] = receiver_email

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login("milliebwari@gmail.com", "aytl kmyh ksxv fliw" )
            server.send_message(msg)
        print(f"[INFO] OTP email successfully sent to {receiver_email}")    
        return True
    except Exception as e:
        print("Email send failed:", e)
        return False

def verify_face(user_id, captured_image):
    try:
        registered_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{user_id}.jpg")
        if not os.path.exists(registered_image_path):
            return False

        registered_img = face_recognition.load_image_file(registered_image_path)
        registered_enc = face_recognition.face_encodings(registered_img)
        if not registered_enc:
            return False

        # Process captured image
        nparr = np.frombuffer(captured_image.read(), np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        rgb_img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        encodings = face_recognition.face_encodings(rgb_img)

        if not encodings:
            return False

        return face_recognition.compare_faces([registered_enc[0]], encodings[0])[0]
    except Exception as e:
        print("Face verification error:", e)
        return False

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            print("[INFO] Received POST request for registration.")

            name = request.form.get('name')
            email = request.form.get('email')
            user_id = request.form.get('user_id')
            password = request.form.get('password')
            face_image = request.files.get('face_image')

            print(f"[DEBUG] name: {name}, email: {email}, user_id: {user_id}, password: {'***' if password else None}")
            print(f"[DEBUG] face_image: {face_image.filename if face_image else 'None'}")

            if not all([name, email, user_id, password, face_image]):
                print("[ERROR] Missing required fields.")
                return jsonify({'error': 'All fields are required'}), 400

            try:
                email = validate_email(email).email
                print(f"[INFO] Validated email: {email}")
            except EmailNotValidError as e:
                print(f"[ERROR] Email validation failed: {e}")
                return jsonify({'error': str(e)}), 400

            if mongo.db.users.find_one({'$or': [{'email': email}, {'user_id': user_id}]}):
                print("[ERROR] Email or User ID already registered.")
                return jsonify({'error': 'Email or User ID already registered'}), 400

            print("[INFO] Processing face image.")
            nparr = np.frombuffer(face_image.read(), np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            if img is None:
                print("[ERROR] Image decode failed.")
                return jsonify({'error': 'Invalid image format'}), 400

            img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            face_locations = face_recognition.face_locations(img_rgb)

            print(f"[INFO] Detected {len(face_locations)} face(s) in the image.")
            if len(face_locations) != 1:
                return jsonify({'error': 'Please provide one clear face image'}), 400

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{user_id}.jpg")
            cv2.imwrite(filepath, img)
            print(f"[INFO] Saved face image at {filepath}")

            encoding = face_recognition.face_encodings(img_rgb, face_locations)[0]
            otp = generate_otp()
            print(f"[INFO] Generated OTP: {otp}")

            user = {
                'name': name,
                'email': email,
                'user_id': user_id,
                'password': generate_password_hash(password),
                'face_path': filepath,
                'face_encoding': encoding.tolist(),
                'email_verified': False,
                'has_voted': False,
                'created_at': datetime.utcnow()
            }

            result = mongo.db.users.insert_one(user)
            print(f"[INFO] User inserted with ID: {result.inserted_id}")

            if not send_otp_email(email, otp):
                print("[ERROR] Failed to send OTP email.")
                return jsonify({'error': 'OTP email send failed'}), 500

            session['verify_user_id'] = user_id
            session['otp'] = otp
            print("[INFO] Registration complete. Redirecting to verify email.")
            return redirect(url_for('verify_email'))

        except Exception as e:
            print(f"[EXCEPTION] Registration failed: {e}")
            return jsonify({'error': 'Something went wrong'}), 500

    return render_template('register.html')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'verify_user_id' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        otp = request.form.get('otp')
        if otp == session.get('otp'):
            mongo.db.users.update_one({'user_id': session['verify_user_id']}, {'$set': {'email_verified': True}})
            session.pop('otp')
            session.pop('verify_user_id')
            flash('Email verified successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Incorrect OTP', 'danger')

    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        face_image = request.files.get('face_image')

        user = mongo.db.users.find_one({'user_id': user_id})
        if not user or not check_password_hash(user['password'], password):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

        if not user.get('email_verified'):
            flash('Please verify your email', 'danger')
            return redirect(url_for('login'))

        if not face_image:
            flash('Please upload your face image', 'danger')
            return redirect(url_for('login'))

        result, error = verify_face(face_image, user['face_encoding'])
        if not result:
            flash(f'Face verification failed: {error}', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user_id
        session['name'] = user['name']
        session['has_voted'] = user.get('has_voted', False)
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('has_voted'):
        return render_template('already_voted.html')

    candidates = list(mongo.db.candidates.find({}))
    return render_template('dashboard.html', candidates=candidates)

@app.route('/vote', methods=['POST'])
def vote():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('has_voted'):
        flash('You have already voted', 'danger')
        return redirect(url_for('dashboard'))

    candidate_id = request.form.get('candidate_id')
    if not candidate_id:
        flash('Invalid candidate selection', 'danger')
        return redirect(url_for('dashboard'))

    mongo.db.votes.insert_one({
        'user_id': session['user_id'],
        'candidate_id': candidate_id,
        'voted_at': datetime.utcnow()
    })

    mongo.db.users.update_one({'user_id': session['user_id']}, {'$set': {'has_voted': True}})
    session['has_voted'] = True
    flash('Vote recorded successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
