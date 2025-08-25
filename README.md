🔐 AES File Encryption Tool
📌 Project Overview

A Python-based application for file encryption and decryption using AES (Advanced Encryption Standard).

Provides a GUI and dashboard for user-friendly interaction.

Built with Flask, supports file uploads, and maintains history tracking in a database.

🚀 Features

🔑 Encrypt & Decrypt files securely with AES

📂 Upload & manage encrypted files

🗂️ File history tracking (database integration)

🌐 Web-based GUI (Flask + HTML/CSS templates)

🔒 Secure key generation & storage

⚙️ Tech Stack

Backend: Python (Flask)

Frontend: HTML, CSS (templates + static files)

Database: SQLite

Security: AES Encryption (PyCryptodome)

Deployment: Render / Heroku

🛠️ Installation & Setup
# Clone the repository
git clone https://github.com/vaishnavikarmegam05/tomycrypto.git
cd tomycrypto

# Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate  # (Windows)
source venv/bin/activate  # (Linux/Mac)

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py


App will be available at: http://127.0.0.1:5000/

📸 Screenshots (optional)

Add a few screenshots of your app here

🌍 Deployment

Live demo: https://your-app-name.onrender.com

📖 Future Enhancements

Add user authentication with JWT

Cloud file storage (AWS S3, GCP, etc.)

Support for multiple encryption algorithms

Role-based access control
🛠️ How to Run the Project Locally

Clone the repository

git clone https://github.com/vaishnavikarmegam05/tomycrypto.git
cd tomycrypto


Create a virtual environment (recommended)

python -m venv venv
venv\Scripts\activate   # For Windows  
source venv/bin/activate  # For Mac/Linux  


Install dependencies

pip install -r requirements.txt


Run the application

python app.py


Open in browser

http://127.0.0.1:5000/

🌍 Deployment (Live Demo)

This project is deployed on Render.

Live Link: 👉 https://your-app-name.onrender.com

Deployed using:

GitHub → Render auto-deploy integration

gunicorn as the production server (gunicorn app:app)
