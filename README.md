# 🗳️ Facial Recognition Voting System

A secure, web-based voting platform built with Flask, MongoDB, and facial recognition. It authenticates users using webcam-captured images and enforces a one-person-one-vote rule with real-time OTP verification and encryption.

---preview---
![Image](https://github.com/user-attachments/assets/b257fb63-d755-42e7-8755-c12c9dbe4228)

## 🚀 Features

-  Face registration and authentication (via webcam + base64)
-  OTP verification via email
-  One-person-one-vote enforcement
-  Real-time vote casting and results display
-  End-to-end encrypted data storage
-  User-friendly interface and feedback
-  Admin dashboard (optional)

---

## 🧱 Tech Stack

- **Backend**: Python, Flask, MongoDB
- **Face Recognition**: `face_recognition`, `Pillow`, `OpenCV`
- **Security**: `cryptography`, `secrets`, OTP verification
- **Frontend**: HTML, CSS, JavaScript (webcam + base64)
- **Deployment**: GitHub

---

## 🛠️ Setup Instructions

### 1. Clone the repository

git clone https://github.com/iammillie-creator/facial-voting-app.git
cd facial-voting-app

### 2. Create a virtual environmentand activate it

python -m venv venv
venv\Scripts\activate # on windows
or source venv/bin/activate # on linux/macOS

### 3. Install dependencies

pip install -r requirements.txt

### 4. Create a .env file

SECRET_KEY=your_secret_key_here
MONGO_URI=mongodb://localhost:27017/voting_system
EMAIL_SENDER=your_email@gmail.com
EMAIL_PASSWORD=your_email_password_or_app_password

### 5. Run the app

python app.py

## Project Structure

├── app.py
├── static/
│   └── face_images/
├── templates/
│   ├── base.html
│   ├── home.html
│   ├── register.html
│   ├── verify_email.html
│   ├── login.html
│   ├── dashboard.html
│   ├── results.html
│   └── already_voted.html
├── .env
├── .gitignore
├── requirements.txt
└── README.md


## Security Considerations
. Facial data is encoded and encrypted before being stored
. OTP is generated per registration and stored in a session
. Votes are protected with end-to-end encryption

## Author
@iammillie-creator
