# app.py
import os, datetime, uuid
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, send_from_directory, abort)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from file_encryptor import encrypt_file, decrypt_file

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "database.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "change_this_to_a_random_secret"  # change in production

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    original_name = db.Column(db.String(300), nullable=False)
    stored_name = db.Column(db.String(300), nullable=False)  # name on disk
    action = db.Column(db.String(20), nullable=False)  # encrypt/decrypt
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

with app.app_context():
    db.create_all()

# Helpers
def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

# Routes
@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("index"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Fill all fields.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))
        u = User(username=username)
        u.set_password(password)
        db.session.add(u); db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            session["username"] = user.username
            flash("Logged in.", "success")
            return redirect(url_for("index"))
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route("/index", methods=["GET","POST"])
@login_required
def index():
    if request.method == "POST":
        mode = request.form.get("mode")
        password = request.form.get("password", "")
        uploaded = request.files.get("file")
        if not uploaded or not password:
            flash("Provide file and password.", "danger")
            return redirect(url_for("index"))

        original_name = secure_filename(uploaded.filename)
        # create unique stored filename to avoid collisions
        stored_base = str(uuid.uuid4())
        saved_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_base + "_" + original_name)
        uploaded.save(saved_path)

        try:
            if mode == "encrypt":
                enc_path, key_path = encrypt_file(saved_path, password)
                enc_fn = os.path.basename(enc_path)
                key_fn = os.path.basename(key_path)
                # record both files as separate records so user can download them
                db.session.add(FileRecord(user_id=session["user_id"], original_name=original_name, stored_name=enc_fn, action="encrypt"))
                db.session.add(FileRecord(user_id=session["user_id"], original_name=original_name + " (key)", stored_name=key_fn, action="encrypt"))
                db.session.commit()
                flash(f'Encrypted. <a href="{url_for("download", filename=enc_fn)}">Download .enc</a> | <a href="{url_for("download", filename=key_fn)}">Download key</a>', "success")
            elif mode == "decrypt":
                keyfile = request.files.get("keyfile")
                if not keyfile:
                    flash("Upload key file for decryption.", "danger")
                    return redirect(url_for("index"))
                key_original = secure_filename(keyfile.filename)
                key_stored = str(uuid.uuid4()) + "_" + key_original
                key_path = os.path.join(app.config["UPLOAD_FOLDER"], key_stored)
                keyfile.save(key_path)
                # attempt decrypt
                out_path = decrypt_file(saved_path, password, key_path)
                out_fn = os.path.basename(out_path)
                db.session.add(FileRecord(user_id=session["user_id"], original_name=original_name, stored_name=out_fn, action="decrypt"))
                db.session.commit()
                flash(f'Decrypted. <a href="{url_for("download", filename=out_fn)}">Download file</a>', "success")
            else:
                flash("Invalid mode.", "danger")
        except Exception as e:
            flash("Operation failed: " + str(e), "danger")
        return redirect(url_for("index"))

    return render_template("index.html", username=session.get("username"))

@app.route("/history")
@login_required
def history():
    user_id = session["user_id"]
    rows = FileRecord.query.filter_by(user_id=user_id).order_by(FileRecord.timestamp.desc()).all()
    return render_template("history.html", history=rows)

@app.route("/download/<path:filename>")
@login_required
def download(filename):
    """
    Only allow users to download files that belong to them.
    """
    # ensure file exists and belongs to this user
    rec = FileRecord.query.filter_by(stored_name=filename, user_id=session["user_id"]).first()
    if not rec:
        abort(403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
