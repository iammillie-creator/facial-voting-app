import os
import random
import string
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import cv2
import face_recognition
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config["MONGO_URI"] = "mongodb://localhost:27017/voting_system"
mongo = PyMongo(app)

# Email configuration 
EMAIL_SENDER = 'lizzyjlo55@gmail.com'
EMAIL_PASSWORD = 'B$rw6!a'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# Configure upload folder for face images
UPLOAD_FOLDER = 'static/face_images'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(receiver_email, otp):
    try:
        msg = MIMEText(f'Your OTP for voting system verification is: {otp}')
        msg['Subject'] = 'Voting System - Email Verification'
        msg['From'] = EMAIL_SENDER
        msg['To'] = receiver_email
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def save_face_image(image, user_id):
    try:
        # Convert image data to numpy array
        nparr = np.frombuffer(image.read(), np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        # Save image
        filename = f"{user_id}.jpg"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        cv2.imwrite(filepath, img)
        return filepath
    except Exception as e:
        print(f"Error saving face image: {e}")
        return None

def verify_face(user_id, captured_image):
    try:
        # Load registered face
        registered_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{user_id}.jpg")
        if not os.path.exists(registered_image_path):
            return False
            
        registered_image = face_recognition.load_image_file(registered_image_path)
        registered_encoding = face_recognition.face_encodings(registered_image)[0]
        
        # Process captured image
        nparr = np.frombuffer(captured_image.read(), np.uint8)
        captured_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        rgb_captured = cv2.cvtColor(captured_img, cv2.COLOR_BGR2RGB)
        
        # Find faces in the captured image
        face_locations = face_recognition.face_locations(rgb_captured)
        if not face_locations:
            return False
            
        captured_encoding = face_recognition.face_encodings(rgb_captured, face_locations)[0]
        
        # Compare faces
        results = face_recognition.compare_faces([registered_encoding], captured_encoding)
        return results[0]
    except Exception as e:
        print(f"Error in face verification: {e}")
        return False

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        print("\nDEBUG - Registration attempt started")

        # Detect if this is a JSON request (from fetch) or a traditional form POST
        if request.content_type == 'application/json':
            try:
                data = request.get_json()
                name = data.get('name')  # Add this if name is sent from frontend
                email = data.get('email')
                user_id = data.get('user_id')
                password = data.get('password')
                face_image_data = data.get('face_image_data')

                print(f"DEBUG - JSON Payload: email={email}, user_id={user_id}")
                print("DEBUG - Face image data received:", bool(face_image_data))
                print(f"DEBUG - First 50 chars of face data: {face_image_data[:50] if face_image_data else 'None'}")

            except Exception as e:
                print(f"DEBUG - JSON parsing failed: {str(e)}")
                return jsonify({'success': False, 'message': 'Invalid JSON data'}), 400
        else:
            return jsonify({'success': False, 'message': 'Unsupported Media Type'}), 415

        # Validate email
        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            print(f"DEBUG - Email validation failed: {str(e)}")
            return jsonify({'success': False, 'message': 'Invalid email address'}), 400

        # Check if user already exists
        existing_user = mongo.db.users.find_one({'$or': [{'email': email}, {'user_id': user_id}]})
        if existing_user:
            print(f"DEBUG - User already exists: {existing_user}")
            return jsonify({'success': False, 'message': 'Email or ID already registered'}), 400

        # Process face image
        if not face_image_data or not isinstance(face_image_data, str) or not face_image_data.startswith('data:image'):
            print("DEBUG - Invalid or missing face image data")
            return jsonify({'success': False, 'message': 'Valid face image is required'}), 400

        try:
            import base64, numpy as np, cv2, os
            header, image_data = face_image_data.split(',', 1)
            image_bytes = base64.b64decode(image_data)
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            filename = f"{user_id}.jpg"
            face_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            cv2.imwrite(face_path, img)
            print(f"DEBUG - Face image saved to: {face_path}")

            is_valid, msg = validate_face_image(face_path)
            if not is_valid:
                os.remove(face_path)
                return jsonify({'success': False, 'message': f'Invalid face image: {msg}'}), 400

            face_encoding = detect_and_encode_face(face_path)
            if face_encoding is None:
                os.remove(face_path)
                return jsonify({'success': False, 'message': 'No face detected in the image'}), 400

        except Exception as e:
            print(f"DEBUG - Face processing error: {str(e)}")
            return jsonify({'success': False, 'message': 'Error processing face image'}), 500

        # Create user
        hashed_password = generate_password_hash(password)
        user_data = {
            'name': name,
            'email': email,
            'user_id': user_id,
            'password': hashed_password,
            'face_image': face_path,
            'face_encoding': face_encoding.tolist(),
            'email_verified': False,
            'has_voted': False,
            'created_at': datetime.utcnow()
        }

        try:
            mongo.db.users.insert_one(user_data)
            print(f"DEBUG - User created successfully: {user_id}")
        except Exception as e:
            print(f"DEBUG - Database error: {str(e)}")
            return jsonify({'success': False, 'message': 'Error creating user account'}), 500

        # Generate and send OTP
        otp = generate_otp()
        session['otp'] = otp
        session['verify_user_id'] = user_id

        if send_otp_email(email, otp):
            print(f"DEBUG - OTP sent to {email}")
            return jsonify({'success': True, 'message': 'Registration successful! Check your email for OTP'}), 200
        else:
            print("DEBUG - Failed to send OTP email")
            return jsonify({'success': False, 'message': 'Error sending OTP email'}), 500

    # Handle GET request
    return render_template('register.html')


@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'verify_user_id' not in session:
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        stored_otp = session.get('otp')
        
        if user_otp == stored_otp:
            # Update user as verified
            mongo.db.users.update_one(
                {'user_id': session['verify_user_id']},
                {'$set': {'email_verified': True}}
            )
            
            # Clean up session
            session.pop('otp')
            session.pop('verify_user_id')
            
            flash('Email verified successfully! You can now login', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP', 'danger')
    
    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        face_image = request.files.get('face_image')
        
        # Find user
        user = mongo.db.users.find_one({'user_id': user_id})
        
        if not user:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
        
        # Check password
        if not check_password_hash(user['password'], password):
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
        
        # Check email verification
        if not user.get('email_verified', False):
            flash('Please verify your email first', 'danger')
            return redirect(url_for('login'))
        
        # Verify face
        if not face_image:
            flash('Face verification required', 'danger')
            return redirect(url_for('login'))
        
        if not verify_face(user_id, face_image):
            flash('Face verification failed', 'danger')
            return redirect(url_for('login'))
        
        # Login successful
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
    
    if session.get('has_voted', False):
        return render_template('already_voted.html')
    
    # Get candidates from database
    candidates = list(mongo.db.candidates.find({}))
    return render_template('dashboard.html', candidates=candidates)

@app.route('/vote', methods=['POST'])
def vote():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('has_voted', False):
        flash('You have already voted', 'danger')
        return redirect(url_for('dashboard'))
    
    candidate_id = request.form.get('candidate_id')
    if not candidate_id:
        flash('Invalid candidate', 'danger')
        return redirect(url_for('dashboard'))
    
    # Record vote
    mongo.db.votes.insert_one({
        'user_id': session['user_id'],
        'candidate_id': candidate_id,
        'voted_at': datetime.utcnow()
    })
    
    # Update user as voted
    mongo.db.users.update_one(
        {'user_id': session['user_id']},
        {'$set': {'has_voted': True}}
    )
    
    session['has_voted'] = True
    flash('Thank you for voting!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)