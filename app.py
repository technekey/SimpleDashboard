import os
import json
import psutil
import glob
import requests
import time
import datetime
import subprocess
import re

from argon2 import PasswordHasher, exceptions as argon2_exceptions
from cryptography.fernet import Fernet
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# 1) Load config from JSON
with open("config.json", "r") as f:
    config_data = json.load(f)

APP_BRAND = config_data["APP_BRAND"]
ADMIN_USERNAME = config_data["ADMIN_USERNAME"]
ADMIN_PASSWORD_HASH = config_data["ADMIN_PASSWORD_HASH"]
HOST = config_data["HOST"]
PORT = config_data["PORT"]

DEBUG_INSIGHTS = bool(config_data.get("DEBUG_INSIGHTS", False))

# 2) We have ciphertext for weather in OPENWEATHER_API_KEY_ENC
encrypted_key = config_data.get("OPENWEATHER_API_KEY_ENC", "").strip()
CITY_NAME = config_data.get("CITY_NAME", "").strip()

# 3) Load Fernet secret from environment to decrypt the weather key
fernet_secret = os.environ.get("FERNET_SECRET")
if not fernet_secret:
    print("WARNING: FERNET_SECRET is not set. Weather key cannot be decrypted.")
    fernet = None
else:
    fernet = Fernet(fernet_secret.encode())

# 4) Attempt to decrypt the weather key, if present
OPENWEATHER_API_KEY = ""
if encrypted_key and fernet:
    try:
        OPENWEATHER_API_KEY = fernet.decrypt(encrypted_key.encode()).decode()
    except Exception as e:
        print("Failed to decrypt weather key:", e)

# 5) Check if weather is enabled
WEATHER_ENABLED = bool(OPENWEATHER_API_KEY and CITY_NAME)
print("Weather enabled?", WEATHER_ENABLED)
print("Debug insights enabled?", DEBUG_INSIGHTS)

ph = PasswordHasher()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///apps.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Create a folder for uploaded icons
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # ensure it exists
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database Model
class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    icon = db.Column(db.String(100), default="fas fa-cubes")

def run_cmd(cmd):
    """Runs a shell command and returns decoded output (including possible ANSI/backspace)."""
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode('utf-8', errors='replace')
    except subprocess.CalledProcessError as e:
        return f"Error running '{cmd}':\n{e.output.decode('utf-8', errors='replace')}"

def sanitize_output(raw):
    """
    Removes backspaces, ANSI color codes, and other control chars (except \n, \r, \t).
    This prevents 'strikethrough' or garbled text in HTML <pre> blocks.
    """
    no_ansi = re.sub(r'\x1B\[[0-9;]*[A-Za-z]', '', raw)
    no_overstrike = re.sub(r'.\x08', '', no_ansi)
    def keep_printable(c):
        if c in ('\n', '\r', '\t'):
            return True
        return ord(c) >= 32 and ord(c) != 127
    final = ''.join(c for c in no_overstrike if keep_printable(c))
    return final

@app.route('/')
def dashboard():
    apps = Application.query.all()
    return render_template(
        'index.html',
        apps=apps,
        brand=APP_BRAND,
        weather_enabled=WEATHER_ENABLED
    )

@app.route('/stats')
def stats():
    cpu_usage = psutil.cpu_percent(interval=0.1)
    mem_info = psutil.virtual_memory()
    mem_usage = mem_info.percent
    disk_info = psutil.disk_usage('/')
    disk_usage = disk_info.percent

    # CPU temp if available
    cpu_temp = None
    if hasattr(psutil, "sensors_temperatures"):
        temps = psutil.sensors_temperatures()
        for sensor_name, entries in temps.items():
            if entries:
                cpu_temp = entries[0].current
                break

    home_dirs = [d for d in glob.glob("/home/*") if os.path.isdir(d)]
    home_count = len(home_dirs)

    # Uptime
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)
    uptime_str = str(datetime.timedelta(seconds=uptime_seconds))

    return jsonify({
        'cpu_usage': cpu_usage,
        'mem_usage': mem_usage,
        'disk_usage': disk_usage,
        'cpu_temp': cpu_temp,
        'home_count': home_count,
        'uptime': uptime_str
    })

@app.route('/weather')
def weather():
    if not WEATHER_ENABLED:
        return jsonify({"error": "Weather not configured"}), 200

    url = f"https://api.openweathermap.org/data/2.5/weather?q={CITY_NAME}&appid={OPENWEATHER_API_KEY}&units=metric"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()

        temperature = data["main"]["temp"]
        description = data["weather"][0]["description"]
        icon = data["weather"][0]["icon"]

        return jsonify({
            "temperature": temperature,
            "description": description,
            "icon": icon
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME:
            try:
                ph.verify(ADMIN_PASSWORD_HASH, password)
                session['logged_in'] = True
                flash('You have successfully logged in.', 'info')
                return redirect(url_for('dashboard'))
            except argon2_exceptions.VerifyMismatchError:
                pass
        flash('Invalid credentials. Please try again.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html', brand=APP_BRAND)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('logged_in'):
        flash('Please log in to access the admin panel.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        url_value = request.form.get('url')
        icon_value = request.form.get('icon')  # from hidden input
        icon_file = request.files.get('icon_file')

        if not name or not url_value:
            flash('Please provide both name and URL.', 'warning')
            return redirect(url_for('admin'))

        # If a file was uploaded, override the FA icon
        if icon_file and icon_file.filename:
            from werkzeug.utils import secure_filename
            filename = secure_filename(icon_file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            icon_file.save(save_path)
            icon_value = f"upload:{filename}"

        new_app = Application(name=name, url=url_value, icon=icon_value)
        db.session.add(new_app)
        db.session.commit()
        flash('Application added successfully.', 'info')
        return redirect(url_for('admin'))

    apps = Application.query.all()
    return render_template('admin.html', apps=apps, brand=APP_BRAND, debug_insights=DEBUG_INSIGHTS)

@app.route('/admin/delete/<int:app_id>', methods=['POST'])
def delete_app(app_id):
    if not session.get('logged_in'):
        flash('Please log in to access the admin panel.', 'warning')
        return redirect(url_for('login'))

    app_to_delete = Application.query.get_or_404(app_id)
    db.session.delete(app_to_delete)
    db.session.commit()
    flash('Application removed successfully.', 'info')
    return redirect(url_for('admin'))

@app.route('/admin/system_info')
def admin_system_info():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 403
    if not DEBUG_INSIGHTS:
        return jsonify({"error": "Debug insights disabled by config"}), 403

    data = {}
    top_raw = run_cmd("TERM=dumb top -b -n 2 -d 0.5")
    data["top"]      = sanitize_output(top_raw)
    data["uptime"]   = sanitize_output(run_cmd("TERM=dumb uptime"))
    data["df"]       = sanitize_output(run_cmd("TERM=dumb df -h"))
    data["free"]     = sanitize_output(run_cmd("TERM=dumb free -m"))
    data["who"]      = sanitize_output(run_cmd("TERM=dumb who -a"))
    data["netstat"]  = sanitize_output(run_cmd("TERM=dumb netstat -tuln"))
    data["meminfo"]  = sanitize_output(run_cmd("cat /proc/meminfo"))
    data["cpuinfo"]  = sanitize_output(run_cmd("cat /proc/cpuinfo"))

    return jsonify(data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host=HOST, port=PORT, debug=True)

