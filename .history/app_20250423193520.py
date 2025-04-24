import os
import random
import string
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import cv2
import insii
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
        print("\nDEBUG - Registration attempt started")  # Debug
        print("Form data:", request.form)  # Debug form fields
        print("Files received:", request.files)  # Debug uploaded files

        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        
        # Get face image data (now from form data instead of files)
        face_data = request.form.get('face_image_data')
        print("DEBUG - Face image data received:", {bool(face_image_data)})  # Debug
        print(f"DEBUG - First 50 chars of face data: {face_image_data[:50] if face_image_data else 'None'}")

        # Validate email
        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            print(f"DEBUG - Email validation failed: {str(e)}")  # Debug
            flash('Invalid email address', 'danger')
            return redirect(url_for('register'))
        
        # Check if user already exists
        existing_user = mongo.db.users.find_one({'$or': [{'email': email}, {'user_id': user_id}]})
        if existing_user:
            print(f"DEBUG - User already exists: {existing_user}")  # Debug
            flash('Email or ID already registered', 'danger')
            return redirect(url_for('register'))
        
        # Process face image
        if not face_image_data or not face_image_data.startswith('data:image/jpeg;base64,'):
            print("DEBUG - Invalid or missing face image data")
            flash('Valid face image is required', 'danger')
            return redirect(url_for('register'))
        
        try:
            # Extract base64 data
            header, data = face_image_data.split(',', 1)
            image_bytes = base64.b64decode(image_data)
            
            # Convert to numpy array
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            # Save image
            filename = f"{user_id}.jpg"
            face_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            cv2.imwrite(face_path, img)
            print(f"DEBUG - Face image saved to: {face_path}")  # Debug
            
            # Validate face quality
            is_valid, msg = validate_face_image(face_path)
            if not is_valid:
                print(f"DEBUG - Face validation failed: {msg}")  # Debug
                os.remove(face_path)
                flash(f'Invalid face image: {msg}', 'danger')
                return redirect(url_for('register'))
            
            # Get face encoding
            face_encoding = detect_and_encode_face(face_path)
            if face_encoding is None:
                print("DEBUG - No face detected in image")  # Debug
                os.remove(face_path)
                flash('No face detected in the image', 'danger')
                return redirect(url_for('register'))
                
        except Exception as e:
            print(f"DEBUG - Face processing error: {str(e)}")  # Debug
            flash('Error processing face image', 'danger')
            return redirect(url_for('register'))
        
        # Create user
        hashed_password = generate_password_hash(password)
        user_data = {
            'name': name,
            'email': email,
            'user_id': user_id,
            'password': hashed_password,
            'face_image': face_path,
            'face_encoding': face_encoding.tolist(),  # Store encoding as list
            'email_verified': False,
            'has_voted': False,
            'created_at': datetime.utcnow()
        }
        
        try:
            mongo.db.users.insert_one(user_data)
            print(f"DEBUG - User created successfully: {user_id}")  # Debug
        except Exception as e:
            print(f"DEBUG - Database error: {str(e)}")  # Debug
            flash('Error creating user account', 'danger')
            return redirect(url_for('register'))
        
        # Generate and send OTP
        otp = generate_otp()
        session['otp'] = otp
        session['verify_user_id'] = user_id
        
        if send_otp_email(email, otp):
            print(f"DEBUG - OTP sent to {email}")  # Debug
            flash('Registration successful! Please check your email for OTP', 'success')
            return redirect(url_for('verify_email'))
        else:
            print("DEBUG - Failed to send OTP email")  # Debug
            flash('Error sending OTP email', 'danger')
            return redirect(url_for('register'))
    
    
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