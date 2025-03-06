import os
import json
import psutil
import glob
from argon2 import PasswordHasher, exceptions as argon2_exceptions

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy

# Load config from JSON
with open("config.json", "r") as f:
    config_data = json.load(f)

APP_BRAND = config_data["APP_BRAND"]
ADMIN_USERNAME = config_data["ADMIN_USERNAME"]
ADMIN_PASSWORD_HASH = config_data["ADMIN_PASSWORD_HASH"]
HOST = config_data["HOST"]
PORT = config_data["PORT"]

ph = PasswordHasher()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'CHANGE-THIS-TO-SOMETHING-LIKE-UUID'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///apps.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(200), nullable=False)

@app.route('/')
def dashboard():
    apps = Application.query.all()
    return render_template('index.html', apps=apps, brand=APP_BRAND)

@app.route('/stats')
def stats():
    """Return JSON stats so the front-end can auto-refresh every few seconds."""
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

    # Count subdirectories in /home
    home_dirs = [
        d for d in glob.glob("/home/*")
        if os.path.isdir(d)
    ]
    home_count = len(home_dirs)

    return jsonify({
        'cpu_usage': cpu_usage,
        'mem_usage': mem_usage,
        'disk_usage': disk_usage,
        'cpu_temp': cpu_temp,
        'home_count': home_count
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME:
            # Verify Argon2 hash
            try:
                ph.verify(ADMIN_PASSWORD_HASH, password)
                session['logged_in'] = True
                flash('You have successfully logged in.', 'info')
                return redirect(url_for('dashboard'))
            except argon2_exceptions.VerifyMismatchError:
                pass  # show invalid credentials
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
        if not name or not url_value:
            flash('Please provide both name and URL.', 'warning')
            return redirect(url_for('admin'))
        new_app = Application(name=name, url=url_value)
        db.session.add(new_app)
        db.session.commit()
        flash('Application added successfully.', 'info')
        return redirect(url_for('admin'))

    apps = Application.query.all()
    return render_template('admin.html', apps=apps, brand=APP_BRAND)

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host=HOST, port=PORT, debug=True)

