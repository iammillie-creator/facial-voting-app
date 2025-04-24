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

@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        try:
            # Check content type
            if 'multipart/form-data' not in request.content_type.lower():
                return jsonify({'error': 'Unsupported Media Type'}), 415

            # Get form data
            name = request.form.get('name')
            email = request.form.get('email')
            user_id = request.form.get('user_id')
            password = request.form.get('password')
            face_image = request.files.get('face_image')

            # Validate required fields
            if not all([name, email, user_id, password]):
                return jsonify({'error': 'All fields are required'}), 400

            if not face_image or face_image.filename == '':
                return jsonify({'error': 'Face image is required'}), 400

            # Validate image file
            allowed_extensions = {'jpg', 'jpeg', 'png'}
            if '.' not in face_image.filename or \
               face_image.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                return jsonify({'error': 'Invalid image format. Only JPG, JPEG, PNG allowed'}), 400

            # Process face image
            try:
                img_bytes = face_image.read()
                nparr = np.frombuffer(img_bytes, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                
                if img is None:
                    return jsonify({'error': 'Invalid image data'}), 400
                
                # Convert to RGB (OpenCV uses BGR by default)
                img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
                
                # Face detection (optional - you might want to verify there's exactly one face)
                face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, 1.3, 5)
                
                if len(faces) == 0:
                    return jsonify({'error': 'No face detected in the image'}), 400
                if len(faces) > 1:
                    return jsonify({'error': 'Multiple faces detected. Please upload an image with only one face'}), 400

                # Save image
                filename = f"{user_id}.jpg"
                face_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Save as JPEG with reasonable quality
                cv2.imwrite(face_path, img, [int(cv2.IMWRITE_JPEG_QUALITY), 90])
                
                # Generate FaceNet embedding (pseudo-code - implement your actual FaceNet logic)
                face_embedding = generate_face_embedding(img_rgb)  # You need to implement this
                
                # Store user data in database (pseudo-code)
                new_user = {
                    'name': name,
                    'email': email,
                    'user_id': user_id,
                    'password': generate_password_hash(password),  # Always hash passwords!
                    'face_path': face_path,
                    'face_embedding': face_embedding.tolist() if face_embedding is not None else None,
                    'created_at': datetime.utcnow()
                }
                
                # Save to your database (this depends on your DB system)
                # db.users.insert_one(new_user)  # For MongoDB
                # or User.create(**new_user)      # For SQLAlchemy
                
                # Send verification email (pseudo-code)
                send_verification_email(email, user_id)
                
                return redirect(url_for('verify_email'))
                
            except Exception as e:
                app.logger.error(f"Image processing error: {str(e)}")
                return jsonify({'error': 'Error processing face image'}), 500
                
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            return jsonify({'error': 'Registration failed. Please try again.'}), 500

    return render_template('register.html')

def generate_face_embedding(image):
    """Generate FaceNet embedding for the face image"""
    # Implement your actual FaceNet embedding generation here
    # This is just a placeholder
    try:
        # Your FaceNet implementation would go here
        # Example:
        # aligned_face = align_face(image)
        # embedding = facenet_model.predict(aligned_face)
        # return embedding
        return np.random.rand(128)  # Dummy embedding for example
    except Exception as e:
        app.logger.error(f"Embedding generation error: {str(e)}")
        return None
    
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