from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
from datetime import datetime, timedelta
import hashlib
import secrets
import os
import csv
import io

from translations import TRANSLATIONS

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=2)

def get_db_path():
    if os.environ.get('RENDER'):
        return '/tmp/university_portal.db'
    else:
        return 'university_portal.db'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_mention(score):
    if score >= 16:
        return "Très Bien"
    elif score >= 14:
        return "Bien"
    elif score >= 12:
        return "Assez Bien"
    elif score >= 10:
        return "Passable"
    else:
        return "Ajourné"

def get_text(key):
    lang = session.get('lang', 'en')
    return TRANSLATIONS.get(lang, {}).get(key, TRANSLATIONS['en'].get(key, key))

def calculate_gpa(student_id):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    c.execute("""
        SELECT g.score, s.coefficient 
        FROM grades g
        JOIN subjects s ON g.subject_id = s.id
        WHERE g.student_id = ?
    """, (student_id,))
    
    grades = c.fetchall()
    conn.close()
    
    if not grades:
        return 0, 0
    
    total_score = sum(g[0] * g[1] for g in grades)
    total_coeff = sum(g[1] for g in grades)
    
    if total_coeff == 0:
        return 0, 0
    
    return round(total_score / total_coeff, 2), total_score

def init_db():
    db_path = get_db_path()
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS super_admin
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  email TEXT,
                  created_at TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS administrators
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  school_name TEXT NOT NULL,
                  region TEXT NOT NULL,
                  email TEXT,
                  created_at TEXT,
                  created_by INTEGER)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS filieres
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  code TEXT UNIQUE NOT NULL,
                  description TEXT,
                  school_id INTEGER,
                  created_at TEXT,
                  created_by INTEGER,
                  FOREIGN KEY (school_id) REFERENCES administrators(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS subjects
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  code TEXT UNIQUE NOT NULL,
                  filiere_id INTEGER NOT NULL,
                  coefficient REAL DEFAULT 1.0,
                  created_at TEXT,
                  created_by INTEGER,
                  FOREIGN KEY (filiere_id) REFERENCES filieres(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS students
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  full_name TEXT NOT NULL,
                  school_id INTEGER,
                  filiere_id INTEGER NOT NULL,
                  class_name TEXT NOT NULL,
                  parent_phone TEXT,
                  password_hash TEXT NOT NULL,
                  student_number TEXT UNIQUE,
                  created_at TEXT,
                  created_by INTEGER,
                  FOREIGN KEY (school_id) REFERENCES administrators(id),
                  FOREIGN KEY (filiere_id) REFERENCES filieres(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS grades
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id INTEGER NOT NULL,
                  subject_id INTEGER NOT NULL,
                  score REAL NOT NULL,
                  term TEXT NOT NULL,
                  year INTEGER NOT NULL,
                  uploaded_by INTEGER,
                  uploaded_at TEXT,
                  verified BOOLEAN DEFAULT 0,
                  FOREIGN KEY (student_id) REFERENCES students(id),
                  FOREIGN KEY (subject_id) REFERENCES subjects(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  user_type TEXT NOT NULL,
                  action TEXT NOT NULL,
                  table_name TEXT,
                  record_id INTEGER,
                  details TEXT,
                  ip_address TEXT,
                  created_at TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS sessions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id TEXT NOT NULL,
                  user_type TEXT NOT NULL,
                  token TEXT NOT NULL,
                  created_at TEXT,
                  expires_at TEXT)''')
    
    try:
        default_password = hash_password('superadmin123')
        c.execute('''INSERT OR IGNORE INTO super_admin (username, password_hash, email, created_at)
                     VALUES (?, ?, ?, ?)''',
                  ('superadmin', default_password, 'superadmin@system.cm', datetime.now().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    
    conn.commit()
    conn.close()

def log_audit(user_id, user_type, action, table_name=None, record_id=None, details=None, ip_address=None):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute('''INSERT INTO audit_log (user_id, user_type, action, table_name, record_id, details, ip_address, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (user_id, user_type, action, table_name, record_id, details, ip_address or request.remote_addr, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def create_session(user_id, user_type):
    token = secrets.token_hex(32)
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    c.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now().isoformat(),))
    
    expires_at = datetime.now() + timedelta(hours=2)
    c.execute('''INSERT INTO sessions (user_id, user_type, token, created_at, expires_at)
                 VALUES (?, ?, ?, ?, ?)''',
              (user_id, user_type, token, datetime.now().isoformat(), expires_at.isoformat()))
    
    conn.commit()
    conn.close()
    return token

def verify_session():
    token = session.get('token')
    if not token:
        return None
    
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT user_id, user_type FROM sessions WHERE token = ? AND expires_at > ?", 
              (token, datetime.now().isoformat()))
    result = c.fetchone()
    conn.close()
    
    if result:
        return {'user_id': result[0], 'user_type': result[1]}
    return None

def login_required(func):
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = verify_session()
        if not user:
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = verify_session()
        if not user:
            return redirect(url_for('login'))
        if user['user_type'] not in ['admin', 'super_admin']:
            return "Access denied. Administrator privileges required.", 403
        return func(*args, **kwargs)
    return wrapper

def super_admin_required(func):
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = verify_session()
        if not user:
            return redirect(url_for('login'))
        if user['user_type'] != 'super_admin':
            return "Access denied. Super administrator privileges required.", 403
        return func(*args, **kwargs)
    return wrapper

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in ['en', 'fr']:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

@app.context_processor
def inject_translations():
    return {'t': get_text, 'session': session}

@app.route('/')
def index():
    user = verify_session()
    if user:
        if user['user_type'] == 'super_admin':
            return redirect(url_for('super_admin_dashboard'))
        elif user['user_type'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_type = request.form['user_type']
        username = request.form['username']
        password = request.form['password']
        password_hash = hash_password(password)
        
        db_path = get_db_path()
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        if user_type == 'super_admin':
            c.execute("SELECT id, username FROM super_admin WHERE username = ? AND password_hash = ?", 
                     (username, password_hash))
            result = c.fetchone()
            if result:
                token = create_session(str(result[0]), 'super_admin')
                session['token'] = token
                session['username'] = username
                log_audit(result[0], 'super_admin', 'LOGIN', ip_address=request.remote_addr)
                conn.close()
                return redirect(url_for('super_admin_dashboard'))
        elif user_type == 'admin':
            c.execute("SELECT id, username FROM administrators WHERE username = ? AND password_hash = ?", 
                     (username, password_hash))
            result = c.fetchone()
            if result:
                token = create_session(str(result[0]), 'admin')
                session['token'] = token
                session['username'] = username
                log_audit(result[0], 'admin', 'LOGIN', ip_address=request.remote_addr)
                conn.close()
                return redirect(url_for('admin_dashboard'))
        else:
            c.execute("SELECT id, full_name FROM students WHERE full_name = ? AND password_hash = ?", 
                     (username, password_hash))
            result = c.fetchone()
            if result:
                token = create_session(str(result[0]), 'student')
                session['token'] = token
                session['username'] = result[1]
                log_audit(result[0], 'student', 'LOGIN', ip_address=request.remote_addr)
                conn.close()
                return redirect(url_for('student_dashboard'))
        
        conn.close()
        return render_template('login.html', error=get_text('invalid_credentials'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    token = session.get('token')
    user = verify_session()
    if token and user:
        log_audit(int(user['user_id']), user['user_type'], 'LOGOUT')
    
    if token:
        db_path = get_db_path()
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    session.clear()
    return redirect(url_for('index'))

@app.route('/super_admin/dashboard')
@super_admin_required
def super_admin_dashboard():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    stats = {
        'total_admins': c.execute("SELECT COUNT(*) FROM administrators").fetchone()[0],
        'total_students': c.execute("SELECT COUNT(*) FROM students").fetchone()[0],
        'total_filieres': c.execute("SELECT COUNT(*) FROM filieres").fetchone()[0],
        'total_subjects': c.execute("SELECT COUNT(*) FROM subjects").fetchone()[0],
        'total_grades': c.execute("SELECT COUNT(*) FROM grades").fetchone()[0]
    }
    
    admins = c.execute("SELECT id, username, school_name, region, created_at FROM administrators ORDER BY id DESC LIMIT 10").fetchall()
    recent_students = c.execute("SELECT id, full_name, class_name, filiere_id, created_at FROM students ORDER BY id DESC LIMIT 10").fetchall()
    
    conn.close()
    
    return render_template('super_admin_dashboard.html', stats=stats, admins=admins, recent_students=recent_students)

@app.route('/super_admin/admins', methods=['GET', 'POST'])
@super_admin_required
def manage_admins():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        school_name = request.form['school_name']
        region = request.form['region']
        email = request.form.get('email', '')
        user_type = request.form.get('user_type', 'admin')
        password_hash = hash_password(password)
        user = verify_session()
        
        try:
            if user_type == 'super_admin':
                c.execute('''INSERT INTO super_admin (username, password_hash, email, created_at)
                             VALUES (?, ?, ?, ?)''',
                          (username, password_hash, email, datetime.now().isoformat()))
                conn.commit()
                log_audit(int(user['user_id']), 'super_admin', 'CREATE_SUPER_ADMIN', 'super_admin', c.lastrowid, f"Created super admin: {username}")
                conn.close()
                return render_template('manage_admins.html', success=f'Super Administrator "{username}" created successfully!')
            else:
                c.execute('''INSERT INTO administrators (username, password_hash, school_name, region, email, created_at, created_by)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (username, password_hash, school_name, region, email, datetime.now().isoformat(), int(user['user_id'])))
                conn.commit()
                log_audit(int(user['user_id']), 'super_admin', 'CREATE_ADMIN', 'administrators', c.lastrowid, f"Created admin: {username}")
                conn.close()
                return render_template('manage_admins.html', success=f'Administrator "{username}" created successfully!')
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('manage_admins.html', error='Username already exists')
    
    admins = c.execute("SELECT id, username, school_name, region, email, created_at FROM administrators ORDER BY username").fetchall()
    super_admins = c.execute("SELECT id, username, email, created_at FROM super_admin WHERE username != 'superadmin' ORDER BY username").fetchall()
    conn.close()
    return render_template('manage_admins.html', admins=admins, super_admins=super_admins)

@app.route('/super_admin/delete_admin/<int:admin_id>')
@super_admin_required
def delete_admin(admin_id):
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT username FROM administrators WHERE id = ?", (admin_id,)).fetchone()
    if admin:
        c.execute("DELETE FROM administrators WHERE id = ?", (admin_id,))
        conn.commit()
        log_audit(int(user['user_id']), 'super_admin', 'DELETE_ADMIN', 'administrators', admin_id, f"Deleted admin: {admin[0]}")
    
    conn.close()
    return redirect(url_for('manage_admins'))

@app.route('/super_admin/delete_super_admin/<int:admin_id>')
@super_admin_required
def delete_super_admin(admin_id):
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT username FROM super_admin WHERE id = ?", (admin_id,)).fetchone()
    if admin and admin[0] == 'superadmin':
        conn.close()
        return render_template('manage_admins.html', error='Cannot delete the main Super Administrator!')
    
    if admin:
        c.execute("DELETE FROM super_admin WHERE id = ?", (admin_id,))
        conn.commit()
        log_audit(int(user['user_id']), 'super_admin', 'DELETE_SUPER_ADMIN', 'super_admin', admin_id, f"Deleted super admin: {admin[0]}")
    
    conn.close()
    return redirect(url_for('manage_admins'))

@app.route('/super_admin/audit_log')
@super_admin_required
def audit_log():
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    logs = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    
    return render_template('audit_log.html', logs=logs)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT school_name, id FROM administrators WHERE id = ?", (user['user_id'],)).fetchone()
    school_id = admin[1]
    
    stats = {
        'total_students': c.execute("SELECT COUNT(*) FROM students WHERE school_id = ?", (school_id,)).fetchone()[0],
        'total_filieres': c.execute("SELECT COUNT(*) FROM filieres WHERE school_id = ?", (school_id,)).fetchone()[0],
        'total_grades': c.execute("SELECT COUNT(*) FROM grades g JOIN students s ON g.student_id = s.id WHERE s.school_id = ?", (school_id,)).fetchone()[0]
    }
    
    students = c.execute("SELECT id, full_name, class_name, filiere_id, created_at FROM students WHERE school_id = ? ORDER BY id DESC LIMIT 10", (school_id,)).fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', stats=stats, students=students, school_name=admin[0])

@app.route('/admin/students', methods=['GET', 'POST'])
@admin_required
def manage_students():
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT id FROM administrators WHERE id = ?", (user['user_id'],)).fetchone()
    school_id = admin[0]
    
    filieres = c.execute("SELECT id, name FROM filieres WHERE school_id = ?", (school_id,)).fetchall()
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        filiere_id = int(request.form['filiere_id'])
        class_name = request.form['class_name']
        parent_phone = request.form.get('parent_phone', '')
        password = request.form['password']
        password_hash = hash_password(password)
        
        c.execute("SELECT COUNT(*) FROM students")
        count = c.fetchone()[0] + 1
        student_number = f"ISG-{datetime.now().year}-{str(count).zfill(4)}"
        
        c.execute('''INSERT INTO students (full_name, school_id, filiere_id, class_name, parent_phone, password_hash, student_number, created_at, created_by)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (full_name, school_id, filiere_id, class_name, parent_phone, password_hash, student_number, datetime.now().isoformat(), int(user['user_id'])))
        conn.commit()
        log_audit(int(user['user_id']), 'admin', 'CREATE_STUDENT', 'students', c.lastrowid, f"Created student: {full_name}")
        conn.close()
        return render_template('manage_students.html', success=f'Student created successfully. Student ID: {student_number}', filieres=filieres)
    
    students = c.execute("SELECT id, full_name, student_number, class_name, filiere_id, parent_phone, created_at FROM students WHERE school_id = ? ORDER BY full_name", (school_id,)).fetchall()
    conn.close()
    return render_template('manage_students.html', students=students, filieres=filieres)

@app.route('/admin/delete_student/<int:student_id>')
@admin_required
def delete_student(student_id):
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    student = c.execute("SELECT full_name FROM students WHERE id = ?", (student_id,)).fetchone()
    if student:
        c.execute("DELETE FROM grades WHERE student_id = ?", (student_id,))
        c.execute("DELETE FROM students WHERE id = ?", (student_id,))
        conn.commit()
        log_audit(int(user['user_id']), 'admin', 'DELETE_STUDENT', 'students', student_id, f"Deleted student: {student[0]}")
    
    conn.close()
    return redirect(url_for('manage_students'))

@app.route('/admin/filieres', methods=['GET', 'POST'])
@admin_required
def manage_filieres():
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT id FROM administrators WHERE id = ?", (user['user_id'],)).fetchone()
    school_id = admin[0]
    
    if request.method == 'POST':
        name = request.form['name']
        code = request.form['code']
        description = request.form.get('description', '')
        
        try:
            c.execute('''INSERT INTO filieres (name, code, description, school_id, created_at, created_by)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (name, code, description, school_id, datetime.now().isoformat(), int(user['user_id'])))
            conn.commit()
            log_audit(int(user['user_id']), 'admin', 'CREATE_FILIERE', 'filieres', c.lastrowid, f"Created filiere: {name}")
            conn.close()
            return render_template('manage_filieres.html', success='Filiere created successfully')
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('manage_filieres.html', error='Filiere code already exists')
    
    filieres = c.execute("SELECT id, name, code, description, created_at FROM filieres WHERE school_id = ? ORDER BY name", (school_id,)).fetchall()
    conn.close()
    return render_template('manage_filieres.html', filieres=filieres)

@app.route('/admin/delete_filiere/<int:filiere_id>')
@admin_required
def delete_filiere(filiere_id):
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    filiere = c.execute("SELECT name FROM filieres WHERE id = ?", (filiere_id,)).fetchone()
    if filiere:
        c.execute("DELETE FROM subjects WHERE filiere_id = ?", (filiere_id,))
        c.execute("DELETE FROM filieres WHERE id = ?", (filiere_id,))
        conn.commit()
        log_audit(int(user['user_id']), 'admin', 'DELETE_FILIERE', 'filieres', filiere_id, f"Deleted filiere: {filiere[0]}")
    
    conn.close()
    return redirect(url_for('manage_filieres'))

@app.route('/admin/subjects', methods=['GET', 'POST'])
@admin_required
def manage_subjects():
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT id FROM administrators WHERE id = ?", (user['user_id'],)).fetchone()
    school_id = admin[0]
    
    filieres = c.execute("SELECT id, name FROM filieres WHERE school_id = ?", (school_id,)).fetchall()
    
    if request.method == 'POST':
        name = request.form['name']
        code = request.form['code']
        filiere_id = int(request.form['filiere_id'])
        coefficient = float(request.form['coefficient'])
        
        try:
            c.execute('''INSERT INTO subjects (name, code, filiere_id, coefficient, created_at, created_by)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (name, code, filiere_id, coefficient, datetime.now().isoformat(), int(user['user_id'])))
            conn.commit()
            log_audit(int(user['user_id']), 'admin', 'CREATE_SUBJECT', 'subjects', c.lastrowid, f"Created subject: {name}")
            conn.close()
            return render_template('manage_subjects.html', success='Subject created successfully', filieres=filieres)
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('manage_subjects.html', error='Subject code already exists', filieres=filieres)
    
    subjects = c.execute("""
        SELECT s.id, s.name, s.code, s.coefficient, f.name 
        FROM subjects s 
        JOIN filieres f ON s.filiere_id = f.id 
        WHERE f.school_id = ? 
        ORDER BY s.name
    """, (school_id,)).fetchall()
    
    conn.close()
    return render_template('manage_subjects.html', subjects=subjects, filieres=filieres)

@app.route('/admin/delete_subject/<int:subject_id>')
@admin_required
def delete_subject(subject_id):
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    subject = c.execute("SELECT name FROM subjects WHERE id = ?", (subject_id,)).fetchone()
    if subject:
        c.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))
        conn.commit()
        log_audit(int(user['user_id']), 'admin', 'DELETE_SUBJECT', 'subjects', subject_id, f"Deleted subject: {subject[0]}")
    
    conn.close()
    return redirect(url_for('manage_subjects'))

@app.route('/admin/grades', methods=['GET', 'POST'])
@admin_required
def manage_grades():
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT id FROM administrators WHERE id = ?", (user['user_id'],)).fetchone()
    school_id = admin[0]
    
    students = c.execute("SELECT id, full_name FROM students WHERE school_id = ? ORDER BY full_name", (school_id,)).fetchall()
    subjects = c.execute("""
        SELECT s.id, s.name, f.name 
        FROM subjects s 
        JOIN filieres f ON s.filiere_id = f.id 
        WHERE f.school_id = ? 
        ORDER BY s.name
    """, (school_id,)).fetchall()
    
    if request.method == 'POST':
        student_name = request.form['student_name']
        subject_id = int(request.form['subject_id'])
        score = float(request.form['score'])
        term = request.form['term']
        year = int(request.form['year'])
        
        if score < 0 or score > 20:
            conn.close()
            return render_template('manage_grades.html', error='Score must be between 0 and 20', students=students, subjects=subjects)
        
        c.execute("SELECT id FROM students WHERE full_name = ? AND school_id = ?", (student_name, school_id))
        student = c.fetchone()
        if not student:
            conn.close()
            return render_template('manage_grades.html', error='Student not found. Please create the student first.', students=students, subjects=subjects)
        
        student_id = student[0]
        
        c.execute("SELECT id FROM grades WHERE student_id = ? AND subject_id = ? AND term = ? AND year = ?", 
                 (student_id, subject_id, term, year))
        if c.fetchone():
            conn.close()
            return render_template('manage_grades.html', error='Grade already exists for this student, subject, term, and year', students=students, subjects=subjects)
        
        c.execute('''INSERT INTO grades (student_id, subject_id, score, term, year, uploaded_by, uploaded_at, verified)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (student_id, subject_id, score, term, year, int(user['user_id']), datetime.now().isoformat(), 1))
        conn.commit()
        
        mention = get_mention(score)
        log_audit(int(user['user_id']), 'admin', 'UPLOAD_GRADE', 'grades', c.lastrowid, f"Uploaded grade for {student_name}: {score}/20 ({mention})")
        
        conn.close()
        return render_template('manage_grades.html', success=f'Grade uploaded successfully. Score: {score}/20 - Mention: {mention}', students=students, subjects=subjects)
    
    conn.close()
    return render_template('manage_grades.html', students=students, subjects=subjects)

@app.route('/admin/bulk_upload', methods=['GET', 'POST'])
@admin_required
def bulk_upload():
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT id FROM administrators WHERE id = ?", (user['user_id'],)).fetchone()
    school_id = admin[0]
    
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            return render_template('bulk_upload.html', error='No file uploaded')
        
        file = request.files['csv_file']
        if file.filename == '':
            return render_template('bulk_upload.html', error='No file selected')
        
        if not file.filename.endswith('.csv'):
            return render_template('bulk_upload.html', error='Please upload a valid CSV file')
        
        try:
            stream = io.StringIO(file.stream.read().decode('UTF8'), newline=None)
            csv_input = csv.reader(stream)
            next(csv_input)
            
            errors = []
            successes = 0
            
            for row in csv_input:
                if len(row) < 5:
                    errors.append(f"Row {csv_input.line_num}: Insufficient columns")
                    continue
                
                student_name = row[0].strip()
                subject_name = row[1].strip()
                score = float(row[2])
                term = row[3].strip()
                year = int(row[4])
                
                if score < 0 or score > 20:
                    errors.append(f"Row {csv_input.line_num}: Score {score} must be between 0 and 20")
                    continue
                
                c.execute("SELECT id FROM students WHERE full_name = ? AND school_id = ?", (student_name, school_id))
                student = c.fetchone()
                if not student:
                    errors.append(f"Row {csv_input.line_num}: Student '{student_name}' not found")
                    continue
                
                c.execute("SELECT id FROM subjects WHERE name = ? AND filiere_id IN (SELECT id FROM filieres WHERE school_id = ?)", 
                         (subject_name, school_id))
                subject = c.fetchone()
                if not subject:
                    errors.append(f"Row {csv_input.line_num}: Subject '{subject_name}' not found")
                    continue
                
                c.execute("SELECT id FROM grades WHERE student_id = ? AND subject_id = ? AND term = ? AND year = ?", 
                         (student[0], subject[0], term, year))
                if c.fetchone():
                    errors.append(f"Row {csv_input.line_num}: Duplicate grade for {student_name} - {subject_name}")
                    continue
                
                c.execute('''INSERT INTO grades (student_id, subject_id, score, term, year, uploaded_by, uploaded_at, verified)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                          (student[0], subject[0], score, term, year, int(user['user_id']), datetime.now().isoformat(), 1))
                successes += 1
            
            conn.commit()
            conn.close()
            
            if errors:
                return render_template('bulk_upload.html', partial_success=f'{successes} grades uploaded successfully', errors=errors)
            else:
                return render_template('bulk_upload.html', success='All grades uploaded successfully!')
                
        except Exception as e:
            conn.close()
            return render_template('bulk_upload.html', error=f'Error processing file: {str(e)}')
    
    conn.close()
    return render_template('bulk_upload.html')

@app.route('/admin/reports')
@admin_required
def admin_reports():
    user = verify_session()
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    admin = c.execute("SELECT id, school_name FROM administrators WHERE id = ?", (user['user_id'],)).fetchone()
    school_id = admin[0]
    
    total_students = c.execute("SELECT COUNT(*) FROM students WHERE school_id = ?", (school_id,)).fetchone()[0]
    
    filieres = c.execute("""
        SELECT f.id, f.name, COUNT(s.id) as student_count 
        FROM filieres f 
        LEFT JOIN students s ON s.filiere_id = f.id 
        WHERE f.school_id = ? 
        GROUP BY f.id, f.name
        ORDER BY student_count DESC
    """, (school_id,)).fetchall()
    
    subjects = c.execute("""
        SELECT s.name, COUNT(g.id) as grade_count, AVG(g.score) as avg_score
        FROM subjects s
        LEFT JOIN grades g ON g.subject_id = s.id
        JOIN filieres f ON s.filiere_id = f.id
        WHERE f.school_id = ?
        GROUP BY s.id, s.name
        ORDER BY avg_score DESC
    """, (school_id,)).fetchall()
    
    conn.close()
    
    return render_template('admin_reports.html', total_students=total_students, filieres=filieres, subjects=subjects, school_name=admin[1])

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    user = verify_session()
    if user['user_type'] != 'student':
        return redirect(url_for('admin_dashboard'))
    
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    student = c.execute("SELECT id, full_name, school_id, class_name, student_number FROM students WHERE id = ?", (user['user_id'],)).fetchone()
    
    if not student:
        conn.close()
        return "Student not found", 404
    
    grades = c.execute("""
        SELECT g.subject_id, s.name as subject_name, g.score, g.term, g.year, s.coefficient
        FROM grades g
        JOIN subjects s ON g.subject_id = s.id
        WHERE g.student_id = ?
        ORDER BY g.year DESC, g.term DESC
    """, (student[0],)).fetchall()
    
    gpa, total_score = calculate_gpa(student[0])
    
    total_subjects = len(grades)
    pass_count = sum(1 for g in grades if g[2] >= 10)
    fail_count = total_subjects - pass_count
    avg_score = sum(g[2] for g in grades) / total_subjects if total_subjects > 0 else 0
    mention = get_mention(avg_score) if total_subjects > 0 else "N/A"
    
    conn.close()
    
    return render_template('student_dashboard.html', 
                          student=student, 
                          grades=grades,
                          gpa=gpa,
                          total_subjects=total_subjects,
                          pass_count=pass_count,
                          fail_count=fail_count,
                          avg_score=round(avg_score, 2),
                          mention=mention)

@app.route('/student/transcript')
@login_required
def student_transcript():
    user = verify_session()
    if user['user_type'] != 'student':
        return redirect(url_for('admin_dashboard'))
    
    db_path = get_db_path()
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    student = c.execute("SELECT id, full_name, school_id, class_name, student_number FROM students WHERE id = ?", (user['user_id'],)).fetchone()
    
    if not student:
        conn.close()
        return "Student not found", 404
    
    grades = c.execute("""
        SELECT s.name as subject_name, g.score, g.term, g.year, s.coefficient
        FROM grades g
        JOIN subjects s ON g.subject_id = s.id
        WHERE g.student_id = ?
        ORDER BY g.year DESC, g.term DESC, s.name
    """, (student[0],)).fetchall()
    
    gpa, total_score = calculate_gpa(student[0])
    avg_score = sum(g[1] for g in grades) / len(grades) if grades else 0
    mention = get_mention(avg_score) if grades else "N/A"
    
    conn.close()
    
    return render_template('student_transcript.html', 
                          student=student, 
                          grades=grades,
                          gpa=gpa,
                          avg_score=round(avg_score, 2),
                          mention=mention,
                          total_subjects=len(grades))

@app.route('/student/change_password', methods=['GET', 'POST'])
@login_required
def student_change_password():
    user = verify_session()
    if user['user_type'] != 'student':
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        current_password = hash_password(request.form['current_password'])
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            return render_template('change_password.html', error='New passwords do not match')
        
        db_path = get_db_path()
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        c.execute("SELECT password_hash FROM students WHERE id = ?", (user['user_id'],))
        stored_hash = c.fetchone()[0]
        
        if stored_hash != current_password:
            conn.close()
            return render_template('change_password.html', error='Current password is incorrect')
        
        c.execute("UPDATE students SET password_hash = ? WHERE id = ?", (hash_password(new_password), user['user_id']))
        conn.commit()
        conn.close()
        
        return render_template('change_password.html', success='Password changed successfully')
    
    return render_template('change_password.html')

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
