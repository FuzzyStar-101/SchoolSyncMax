from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os
import json
import pandas as pd
import cloudinary
import cloudinary.uploader
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration
import logging
from logging.handlers import RotatingFileHandler
import re

# Import config
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize Sentry for error tracking
if app.config['SENTRY_DSN']:
    sentry_sdk.init(
        dsn=app.config['SENTRY_DSN'],
        integrations=[FlaskIntegration()],
        traces_sample_rate=0.1,
        profiles_sample_rate=0.1,
    )

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False, 
                    message_queue=app.config['SOCKETIO_MESSAGE_QUEUE'])

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=app.config['RATELIMIT_STORAGE_URL']
)

# Initialize session
app.config['SESSION_SQLALCHEMY'] = db
Session(app)

# Configure Cloudinary
if app.config['CLOUDINARY_CLOUD_NAME']:
    cloudinary.config(
        cloud_name=app.config['CLOUDINARY_CLOUD_NAME'],
        api_key=app.config['CLOUDINARY_API_KEY'],
        api_secret=app.config['CLOUDINARY_API_SECRET'],
        secure=True
    )

# Setup logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/schoolsync.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('SchoolSync Pro startup')

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.String(20), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), nullable=False, index=True)
    class_name = db.Column(db.String(50))
    subjects = db.Column(db.Text)
    avatar_type = db.Column(db.String(20), default='initial')
    avatar_data = db.Column(db.Text)
    first_login = db.Column(db.Boolean, default=True)
    last_password_change = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Homework(db.Model):
    __tablename__ = 'homework'
    id = db.Column(db.String(50), primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    date_given = db.Column(db.Date, nullable=False)
    due_date = db.Column(db.Date, nullable=False, index=True)
    class_name = db.Column(db.String(50), nullable=False, index=True)
    created_by = db.Column(db.String(20), db.ForeignKey('users.user_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Grade(db.Model):
    __tablename__ = 'grades'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False, index=True)
    subject = db.Column(db.String(100), nullable=False)
    test_type = db.Column(db.String(20), nullable=False)
    score = db.Column(db.Float, nullable=False)
    max_score = db.Column(db.Float, default=100)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Schedule(db.Model):
    __tablename__ = 'schedule'
    id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(50), nullable=False, index=True)
    day = db.Column(db.String(20), nullable=False)
    period = db.Column(db.Integer, nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.String(20), db.ForeignKey('users.user_id'))

class TaskList(db.Model):
    __tablename__ = 'task_lists'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    color = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey('task_lists.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatRoom(db.Model):
    __tablename__ = 'chat_rooms'
    room_id = db.Column(db.String(50), primary_key=True)
    room_name = db.Column(db.String(200))
    room_type = db.Column(db.String(20), nullable=False)
    members = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.String(20), db.ForeignKey('users.user_id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_message = db.Column(db.Text)
    last_message_at = db.Column(db.DateTime)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False)
    room_id = db.Column(db.String(50), db.ForeignKey('chat_rooms.room_id'), nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read = db.Column(db.Boolean, default=False)

class Subject(db.Model):
    __tablename__ = 'subjects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Class(db.Model):
    __tablename__ = 'classes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    section = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TeacherSubject(db.Model):
    __tablename__ = 'teacher_subjects'
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.String(20), db.ForeignKey('users.user_id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

# Create tables and super admin
with app.app_context():
    db.create_all()
    
    # Create super admin if doesn't exist
    super_admin = User.query.filter_by(username='superadmin').first()
    if not super_admin:
        super_admin = User(
            user_id='SA001',
            username='superadmin',
            password_hash=generate_password_hash('superadmin123'),
            name='Super Admin',
            role='superadmin',
            avatar_type='initial',
            avatar_data='SA',
            first_login=True
        )
        db.session.add(super_admin)
        db.session.commit()
        app.logger.info('Super admin created')

# Helper Functions
def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if not text:
        return text
    # Remove potentially dangerous characters
    text = re.sub(r'[<>"\']', '', str(text))
    return text.strip()

def validate_email(email):
    """Validate email format"""
    if not email:
        return True
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def generate_user_id(role):
    """Generate unique user ID"""
    prefix_map = {
        'student': 'S',
        'teacher': 'T',
        'admin': 'A',
        'superadmin': 'SA'
    }
    prefix = prefix_map.get(role, 'U')
    
    last_user = User.query.filter(User.user_id.like(f'{prefix}%')).order_by(User.user_id.desc()).first()
    
    if last_user:
        try:
            num = int(last_user.user_id[len(prefix):]) + 1
        except:
            num = 1
    else:
        num = 1
    
    return f"{prefix}{num:03d}"

def upload_to_cloudinary(file_data, folder="avatars"):
    """Upload file to Cloudinary"""
    if not app.config['CLOUDINARY_CLOUD_NAME']:
        return None
    
    try:
        result = cloudinary.uploader.upload(file_data, folder=folder)
        return result['secure_url']
    except Exception as e:
        app.logger.error(f"Cloudinary upload error: {e}")
        return None

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                return jsonify({'success': False, 'message': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_context():
    """Get user context for templates"""
    user = User.query.filter_by(user_id=session.get('user_id')).first()
    if user:
        return {
            'user': {
                'user_id': user.user_id,
                'name': user.name,
                'username': user.username,
                'role': user.role,
                'class': user.class_name or '',
                'first_login': user.first_login
            }
        }
    return {'user': {}}

# Routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = sanitize_input(data.get('username'))
        password = data.get('password')
        role = data.get('role', 'student')
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and check_password_hash(user.password_hash, password):
            if role == 'admin' and user.role not in ['admin', 'superadmin']:
                return jsonify({'success': False, 'message': 'Invalid admin credentials'})
            
            session.clear()
            session['user_id'] = user.user_id
            session['username'] = user.username
            session['role'] = user.role
            session['name'] = user.name
            session['class'] = user.class_name
            session.permanent = True
            
            app.logger.info(f"User {username} logged in")
            
            redirect_map = {
                'student': '/dashboard/account',
                'teacher': '/dashboard/account',
                'admin': '/dashboard/accounts',
                'superadmin': '/dashboard/accounts'
            }
            
            return jsonify({
                'success': True,
                'redirect': redirect_map.get(user.role, '/dashboard/account')
            })
        
        app.logger.warning(f"Failed login attempt for {username}")
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    app.logger.info(f"User {user_id} logged out")
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('account'))

# Dashboard Routes
@app.route('/dashboard/account')
@login_required
def account():
    return render_template('account.html', **get_user_context())

@app.route('/dashboard/schedule')
@login_required
def schedule():
    return render_template('schedule.html', **get_user_context())

@app.route('/dashboard/calendar')
@login_required
def calendar():
    if session.get('role') != 'student':
        return redirect(url_for('schedule'))
    return render_template('calendar.html', **get_user_context())

@app.route('/dashboard/homework')
@login_required
def homework():
    return render_template('homework.html', **get_user_context())

@app.route('/dashboard/grades')
@login_required
def grades():
    return render_template('grades.html', **get_user_context())

@app.route('/dashboard/tasks')
@login_required
def tasks():
    return render_template('tasks.html', **get_user_context())

@app.route('/dashboard/chat')
@login_required
def chat():
    return render_template('chat.html', **get_user_context())

@app.route('/dashboard/accounts')
@login_required
@role_required(['admin', 'superadmin'])
def accounts_mgmt():
    return render_template('accounts_mgmt.html', **get_user_context())

@app.route('/dashboard/import')
@login_required
@role_required(['admin', 'superadmin'])
def data_import():
    return render_template('data_import.html', **get_user_context())

@app.route('/dashboard/timetable')
@login_required
@role_required(['admin', 'superadmin'])
def timetable_editor():
    return render_template('timetable_editor.html', **get_user_context())

@app.route('/dashboard/monitor-chats')
@login_required
@role_required(['superadmin'])
def monitor_chats():
    return render_template('monitor_chats.html', **get_user_context())

# API Endpoints
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Get CSRF token for AJAX requests"""
    token = generate_csrf()
    return jsonify({'csrf_token': token})

@app.route('/api/account', methods=['GET'])
@login_required
@limiter.limit("30 per minute")
def get_account():
    user = User.query.filter_by(user_id=session['user_id']).first()
    
    if user:
        return jsonify({
            'user_id': user.user_id,
            'name': user.name,
            'role': user.role,
            'class': user.class_name or '',
            'subjects': user.subjects or '',
            'username': user.username,
            'first_login': user.first_login
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/profile', methods=['GET', 'PUT'])
@login_required
@limiter.limit("20 per minute")
def profile():
    user = User.query.filter_by(user_id=session['user_id']).first()
    
    if request.method == 'GET':
        if user:
            return jsonify({
                'name': user.name,
                'username': user.username,
                'avatar_type': user.avatar_type,
                'avatar_data': user.avatar_data
            })
        return jsonify({'error': 'User not found'}), 404
    
    elif request.method == 'DELETE':
        hw_id = request.args.get('id')
        Homework.query.filter_by(id=hw_id).delete()
        db.session.commit()
        return jsonify({'success': True})

# Grades
@app.route('/api/grades', methods=['GET', 'POST'])
@login_required
@limiter.limit("60 per minute")
def grades_api():
    if request.method == 'GET':
        student_id = request.args.get('student_id', session['user_id'])
        grades = Grade.query.filter_by(student_id=student_id).all()
        
        grades_dict = {}
        for g in grades:
            if g.subject not in grades_dict:
                grades_dict[g.subject] = {}
            grades_dict[g.subject][g.test_type] = g.score
        
        return jsonify(grades_dict)
    
    elif request.method == 'POST':
        data = request.get_json()
        grade = Grade(
            student_id=data['student_id'],
            subject=sanitize_input(data['subject']),
            test_type=data['test_type'],
            score=float(data['score']),
            max_score=float(data.get('max_score', 100))
        )
        db.session.add(grade)
        db.session.commit()
        return jsonify({'success': True})

# Chat APIs
@app.route('/api/chat/users', methods=['GET'])
@login_required
@limiter.limit("30 per minute")
def search_users():
    query = request.args.get('q', '')
    if len(query) < 2:
        return jsonify([])
    
    users = User.query.filter(
        User.user_id != session['user_id'],
        User.is_active == True,
        db.or_(
            User.name.ilike(f'%{query}%'),
            User.username.ilike(f'%{query}%')
        )
    ).limit(20).all()
    
    return jsonify([{
        'user_id': u.user_id,
        'name': u.name,
        'username': u.username,
        'role': u.role
    } for u in users])

@app.route('/api/chat/rooms', methods=['GET', 'POST'])
@login_required
@limiter.limit("60 per minute")
def chat_rooms():
    if request.method == 'GET':
        rooms = ChatRoom.query.filter(ChatRoom.members.like(f'%{session["user_id"]}%')).all()
        
        result = []
        for room in rooms:
            members = room.members.split(',')
            if room.room_type == 'direct':
                other_id = [m for m in members if m != session['user_id']][0]
                other_user = User.query.filter_by(user_id=other_id).first()
                name = other_user.name if other_user else other_id
            else:
                name = room.room_name
            
            result.append({
                'room_id': room.room_id,
                'room_name': name,
                'room_type': room.room_type,
                'last_message': room.last_message or ''
            })
        
        return jsonify(result)
    
    elif request.method == 'POST':
        data = request.get_json()
        room_type = data['room_type']
        members = sorted(data['members'])
        
        if room_type == 'direct':
            members_str = ','.join(sorted(members))
            existing = ChatRoom.query.filter_by(room_type='direct', members=members_str).first()
            
            if existing:
                return jsonify({'success': True, 'room_id': existing.room_id})
            
            room_id = f"R{int(datetime.utcnow().timestamp())}"
            room_name = 'Direct Chat'
        else:
            room_id = f"R{int(datetime.utcnow().timestamp())}"
            room_name = sanitize_input(data['room_name'])
            members_str = ','.join(members)
        
        room = ChatRoom(
            room_id=room_id,
            room_name=room_name,
            room_type=room_type,
            members=members_str,
            created_by=session['user_id']
        )
        db.session.add(room)
        db.session.commit()
        
        return jsonify({'success': True, 'room_id': room_id})

@app.route('/api/chat/messages/<room_id>', methods=['GET'])
@login_required
@limiter.limit("60 per minute")
def get_messages(room_id):
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    messages = Message.query.filter_by(room_id=room_id).order_by(
        Message.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    result = []
    for m in reversed(messages.items):
        user = User.query.filter_by(user_id=m.sender_id).first()
        result.append({
            'sender_id': m.sender_id,
            'sender_name': user.name if user else 'Unknown',
            'message': m.message,
            'timestamp': m.timestamp.isoformat()
        })
    
    return jsonify(result)

# Super Admin APIs
@app.route('/api/superadmin/all-chats', methods=['GET'])
@login_required
@role_required(['superadmin'])
def get_all_chats():
    rooms = ChatRoom.query.all()
    
    result = []
    for room in rooms:
        count = Message.query.filter_by(room_id=room.room_id).count()
        result.append({
            'room_id': room.room_id,
            'room_name': room.room_name,
            'room_type': room.room_type,
            'message_count': count
        })
    
    return jsonify(result)

@app.route('/api/superadmin/chat-messages/<room_id>', methods=['GET'])
@login_required
@role_required(['superadmin'])
def get_admin_messages(room_id):
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp).all()
    
    result = []
    for m in messages:
        user = User.query.filter_by(user_id=m.sender_id).first()
        result.append({
            'sender_id': m.sender_id,
            'sender_name': user.name if user else 'Unknown',
            'message': m.message,
            'timestamp': m.timestamp.isoformat()
        })
    
    return jsonify(result)

# Admin APIs
@app.route('/api/admin/accounts', methods=['GET', 'POST', 'DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
@limiter.limit("30 per minute")
def admin_accounts():
    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        per_page = 100
        
        query = User.query
        if session['role'] == 'admin':
            query = query.filter(User.role != 'superadmin')
        
        users = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify([{
            'user_id': u.user_id,
            'name': u.name,
            'role': u.role,
            'class': u.class_name or '',
            'subjects': u.subjects or '',
            'username': u.username
        } for u in users.items])
    
    elif request.method == 'POST':
        data = request.get_json()
        user_id = generate_user_id(data['role'])
        
        # Validate email
        email = data.get('email', '')
        if email and not validate_email(email):
            return jsonify({'success': False, 'message': 'Invalid email format'})
        
        # Check username uniqueness
        existing = User.query.filter_by(username=data['username']).first()
        if existing:
            return jsonify({'success': False, 'message': 'Username already exists'})
        
        user = User(
            user_id=user_id,
            username=sanitize_input(data['username']),
            password_hash=generate_password_hash(data['password']),
            name=sanitize_input(data['name']),
            role=data['role'],
            class_name=sanitize_input(data.get('class', '')),
            subjects=sanitize_input(data.get('subjects', '')),
            email=sanitize_input(email),
            avatar_type='initial',
            avatar_data=data['name'][0].upper()
        )
        db.session.add(user)
        db.session.commit()
        
        app.logger.info(f"Admin {session['user_id']} created user {user_id}")
        return jsonify({'success': True, 'user_id': user_id})
    
    elif request.method == 'DELETE':
        user_id = request.args.get('id')
        
        # Prevent deleting super admin
        if user_id == 'SA001':
            return jsonify({'success': False, 'message': 'Cannot delete super admin'})
        
        User.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        
        app.logger.info(f"Admin {session['user_id']} deleted user {user_id}")
        return jsonify({'success': True})

@app.route('/api/admin/subjects', methods=['GET', 'POST', 'DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_subjects():
    if request.method == 'GET':
        subjects = Subject.query.order_by(Subject.name).all()
        return jsonify([{'name': s.name, 'code': s.code} for s in subjects])
    
    elif request.method == 'POST':
        data = request.get_json()
        subject = Subject(
            name=sanitize_input(data['name']),
            code=sanitize_input(data.get('code', ''))
        )
        db.session.add(subject)
        db.session.commit()
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        name = request.args.get('name')
        Subject.query.filter_by(name=name).delete()
        db.session.commit()
        return jsonify({'success': True})

@app.route('/api/admin/classes-list', methods=['GET', 'POST', 'DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_classes():
    if request.method == 'GET':
        classes = Class.query.order_by(Class.name).all()
        return jsonify([{'name': c.name, 'section': c.section} for c in classes])
    
    elif request.method == 'POST':
        data = request.get_json()
        cls = Class(
            name=sanitize_input(data['name']),
            section=sanitize_input(data.get('section', ''))
        )
        db.session.add(cls)
        db.session.commit()
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        name = request.args.get('name')
        Class.query.filter_by(name=name).delete()
        db.session.commit()
        return jsonify({'success': True})

@app.route('/api/admin/teacher-subjects', methods=['GET', 'POST', 'DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
def teacher_subjects():
    if request.method == 'GET':
        assignments = db.session.query(
            TeacherSubject, User
        ).join(User, TeacherSubject.teacher_id == User.user_id).all()
        
        return jsonify([{
            'id': ts.id,
            'teacher_id': ts.teacher_id,
            'teacher_name': u.name,
            'subject': ts.subject
        } for ts, u in assignments])
    
    elif request.method == 'POST':
        data = request.get_json()
        ts = TeacherSubject(
            teacher_id=data['teacher_id'],
            subject=sanitize_input(data['subject'])
        )
        db.session.add(ts)
        db.session.commit()
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        assignment_id = request.args.get('id')
        TeacherSubject.query.filter_by(id=assignment_id).delete()
        db.session.commit()
        return jsonify({'success': True})

@app.route('/api/admin/teachers-list', methods=['GET'])
@login_required
@role_required(['admin', 'superadmin'])
def teachers_list():
    teachers = User.query.filter_by(role='teacher').order_by(User.name).all()
    return jsonify([{'id': t.user_id, 'name': t.name} for t in teachers])

@app.route('/api/admin/upload', methods=['POST'])
@login_required
@role_required(['admin', 'superadmin'])
@limiter.limit("10 per hour")
def upload_data():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'})
    
    file = request.files['file']
    data_type = request.form.get('data_type', 'auto-detect')
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'})
    
    filename = file.filename
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(filepath)
    
    try:
        if filename.endswith('.csv'):
            df = pd.read_csv(filepath)
        elif filename.endswith('.xlsx'):
            df = pd.read_excel(filepath)
        elif filename.endswith('.json'):
            df = pd.read_json(filepath)
        else:
            return jsonify({'success': False, 'message': 'Unsupported file format'})
        
        df.columns = df.columns.str.lower().str.strip().str.replace(' ', '_')
        
        if data_type == 'auto-detect':
            if 'class' in df.columns and 'student' in str(df.columns).lower():
                data_type = 'students'
            elif 'subjects' in df.columns or 'teacher' in str(df.columns).lower():
                data_type = 'teachers'
        
        records = 0
        errors = []
        
        if data_type == 'students':
            for idx, row in df.iterrows():
                try:
                    name = str(row.get('name', f'Student {idx}'))
                    class_name = str(row.get('class', ''))
                    username = str(row.get('username', name.lower().replace(' ', '')))
                    password = str(row.get('password', 'student123'))
                    
                    # Check if username exists
                    if User.query.filter_by(username=username).first():
                        errors.append(f"Row {idx + 1}: Username {username} already exists")
                        continue
                    
                    user_id = generate_user_id('student')
                    
                    user = User(
                        user_id=user_id,
                        username=username,
                        password_hash=generate_password_hash(password),
                        name=name,
                        role='student',
                        class_name=class_name,
                        email=sanitize_input(str(row.get('email', ''))) if pd.notna(row.get('email')) else '',
                        phone=sanitize_input(str(row.get('phone', ''))) if pd.notna(row.get('phone')) else '',
                        avatar_type='initial',
                        avatar_data=name[0].upper()
                    )
                    db.session.add(user)
                    records += 1
                except Exception as e:
                    errors.append(f"Row {idx + 1}: {str(e)}")
        
        elif data_type == 'teachers':
            for idx, row in df.iterrows():
                try:
                    name = str(row.get('name', f'Teacher {idx}'))
                    subjects = str(row.get('subjects', '')) if pd.notna(row.get('subjects')) else ''
                    username = str(row.get('username', name.lower().replace(' ', '')))
                    password = str(row.get('password', 'teacher123'))
                    
                    if User.query.filter_by(username=username).first():
                        errors.append(f"Row {idx + 1}: Username {username} already exists")
                        continue
                    
                    user_id = generate_user_id('teacher')
                    
                    user = User(
                        user_id=user_id,
                        username=username,
                        password_hash=generate_password_hash(password),
                        name=name,
                        role='teacher',
                        subjects=subjects,
                        avatar_type='initial',
                        avatar_data=name[0].upper()
                    )
                    db.session.add(user)
                    records += 1
                except Exception as e:
                    errors.append(f"Row {idx + 1}: {str(e)}")
        
        db.session.commit()
        
        # Clean up uploaded file
        try:
            os.remove(filepath)
        except:
            pass
        
        message = f"Successfully imported {records} records"
        if errors:
            message += f". {len(errors)} errors occurred."
        
        app.logger.info(f"Data import: {records} records, {len(errors)} errors")
        
        return jsonify({
            'success': True,
            'message': message,
            'records': records,
            'errors': errors[:10]  # Limit errors to first 10
        })
    
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({'success': False, 'message': str(e)})

# Socket.IO Events
@socketio.on('join_room')
def handle_join_room(data):
    room_id = data['room_id']
    join_room(room_id)
    emit('user_joined', {
        'user_id': session['user_id'],
        'name': session['name']
    }, room=room_id, skip_sid=request.sid)

@socketio.on('leave_room')
def handle_leave_room(data):
    room_id = data['room_id']
    leave_room(room_id)
    emit('user_left', {
        'user_id': session['user_id'],
        'name': session['name']
    }, room=room_id)

@socketio.on('send_message')
def handle_send_message(data):
    room_id = data['room_id']
    message_text = sanitize_input(data['message'])
    
    # Save to database
    message = Message(
        sender_id=session['user_id'],
        room_id=room_id,
        message=message_text
    )
    db.session.add(message)
    
    # Update room last message
    room = ChatRoom.query.filter_by(room_id=room_id).first()
    if room:
        room.last_message = message_text[:50]
        room.last_message_at = datetime.utcnow()
    
    db.session.commit()
    
    # Broadcast
    emit('receive_message', {
        'sender_id': session['user_id'],
        'sender_name': session['name'],
        'message': message_text,
        'timestamp': message.timestamp.isoformat()
    }, room=room_id)

@socketio.on('typing')
def handle_typing(data):
    room_id = data['room_id']
    emit('user_typing', {
        'user_id': session['user_id'],
        'name': session['name']
    }, room=room_id, skip_sid=request.sid)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    room_id = data['room_id']
    emit('user_stop_typing', {
        'user_id': session['user_id']
    }, room=room_id, skip_sid=request.sid)

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('login.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    app.logger.error(f"Internal error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=app.config['DEBUG'])'PUT':
        data = request.get_json()
        name = sanitize_input(data.get('name'))
        username = sanitize_input(data.get('username'))
        avatar_type = data.get('avatar_type', 'initial')
        avatar_data = data.get('avatar_data', '')
        
        if not name or not username:
            return jsonify({'success': False, 'message': 'Name and username required'})
        
        # Check username uniqueness
        existing = User.query.filter_by(username=username).filter(User.user_id != session['user_id']).first()
        if existing:
            return jsonify({'success': False, 'message': 'Username already taken'})
        
        username_changed = (user.username != username)
        
        # Handle avatar upload to Cloudinary
        if avatar_type == 'uploaded' and avatar_data.startswith('data:image'):
            cloud_url = upload_to_cloudinary(avatar_data)
            if cloud_url:
                avatar_data = cloud_url
        
        user.name = name
        user.username = username
        user.avatar_type = avatar_type
        user.avatar_data = avatar_data
        
        db.session.commit()
        
        session['name'] = name
        session['username'] = username
        
        app.logger.info(f"User {user.user_id} updated profile")
        
        return jsonify({'success': True, 'username_changed': username_changed})

@app.route('/api/change-password', methods=['POST'])
@login_required
@limiter.limit("5 per hour")
def change_password():
    data = request.get_json()
    current = data.get('current_password')
    new = data.get('new_password')
    
    if len(new) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'})
    
    user = User.query.filter_by(user_id=session['user_id']).first()
    
    if user and check_password_hash(user.password_hash, current):
        user.password_hash = generate_password_hash(new)
        user.last_password_change = datetime.utcnow()
        user.first_login = False
        db.session.commit()
        
        app.logger.info(f"User {user.user_id} changed password")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Current password is incorrect'})

@app.route('/api/admin/reset-password', methods=['POST'])
@login_required
@role_required(['admin', 'superadmin'])
@limiter.limit("10 per hour")
def reset_password():
    data = request.get_json()
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'})
    
    user = User.query.filter_by(user_id=user_id).first()
    if user:
        user.password_hash = generate_password_hash(new_password)
        user.last_password_change = datetime.utcnow()
        db.session.commit()
        
        app.logger.info(f"Admin {session['user_id']} reset password for {user_id}")
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'User not found'})

# Task Lists
@app.route('/api/task-lists', methods=['GET', 'POST', 'DELETE'])
@login_required
@limiter.limit("60 per minute")
def task_lists():
    if request.method == 'GET':
        lists = TaskList.query.filter_by(user_id=session['user_id']).all()
        result = []
        for lst in lists:
            tasks = Task.query.filter_by(list_id=lst.id).order_by(Task.created_at).all()
            result.append({
                'id': lst.id,
                'name': lst.name,
                'color': lst.color,
                'tasks': [{
                    'id': t.id,
                    'text': t.text,
                    'notes': t.notes,
                    'completed': t.completed
                } for t in tasks]
            })
        return jsonify(result)
    
    elif request.method == 'POST':
        data = request.get_json()
        name = sanitize_input(data.get('name'))
        color = data.get('color')
        
        task_list = TaskList(user_id=session['user_id'], name=name, color=color)
        db.session.add(task_list)
        db.session.commit()
        
        return jsonify({'success': True, 'id': task_list.id})
    
    elif request.method == 'DELETE':
        list_id = request.args.get('id')
        TaskList.query.filter_by(id=list_id, user_id=session['user_id']).delete()
        db.session.commit()
        return jsonify({'success': True})

@app.route('/api/tasks', methods=['POST', 'PUT', 'DELETE'])
@login_required
@limiter.limit("60 per minute")
def tasks_api():
    if request.method == 'POST':
        data = request.get_json()
        task = Task(
            list_id=data['list_id'],
            user_id=session['user_id'],
            text=sanitize_input(data['text']),
            notes=sanitize_input(data.get('notes', ''))
        )
        db.session.add(task)
        db.session.commit()
        return jsonify({'success': True, 'id': task.id})
    
    elif request.method == 'PUT':
        data = request.get_json()
        task = Task.query.filter_by(id=data['id'], user_id=session['user_id']).first()
        if task and 'completed' in data:
            task.completed = data['completed']
            db.session.commit()
            return jsonify({'success': True})
        return jsonify({'success': False})
    
    elif request.method == 'DELETE':
        task_id = request.args.get('id')
        Task.query.filter_by(id=task_id, user_id=session['user_id']).delete()
        db.session.commit()
        return jsonify({'success': True})

# Schedule
@app.route('/api/schedule', methods=['GET'])
@login_required
@limiter.limit("60 per minute")
def get_schedule():
    user_class = request.args.get('class', session.get('class', ''))
    
    schedules = Schedule.query.filter_by(class_name=user_class).order_by(Schedule.day, Schedule.period).all()
    
    schedule_dict = {}
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    for day in days:
        schedule_dict[day] = [''] * 8
    
    for s in schedules:
        if s.day in schedule_dict and 0 <= s.period - 1 < 8:
            schedule_dict[s.day][s.period - 1] = s.subject
    
    return jsonify(schedule_dict)

@app.route('/api/admin/schedule', methods=['GET', 'PUT'])
@login_required
@role_required(['admin', 'superadmin'])
@limiter.limit("30 per minute")
def admin_schedule():
    if request.method == 'GET':
        class_name = request.args.get('class', '')
        schedules = Schedule.query.filter_by(class_name=class_name).all()
        
        schedule_dict = {}
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        for day in days:
            schedule_dict[day] = [''] * 8
        
        for s in schedules:
            if s.day in schedule_dict and 0 <= s.period - 1 < 8:
                schedule_dict[s.day][s.period - 1] = s.subject
        
        return jsonify(schedule_dict)
    
    elif request.method == 'PUT':
        data = request.get_json()
        class_name = sanitize_input(data['class'])
        schedule = data['schedule']
        
        # Delete existing schedule
        Schedule.query.filter_by(class_name=class_name).delete()
        
        # Insert new schedule
        for day, subjects in schedule.items():
            for period, subject in enumerate(subjects, 1):
                if subject:
                    s = Schedule(class_name=class_name, day=day, period=period, subject=subject)
                    db.session.add(s)
        
        db.session.commit()
        app.logger.info(f"Schedule updated for class {class_name}")
        return jsonify({'success': True})

@app.route('/api/admin/check-conflicts', methods=['POST'])
@login_required
@role_required(['admin', 'superadmin'])
def check_conflicts():
    data = request.get_json()
    class_name = data['class']
    day = data['day']
    period = data['period']
    subject = data['subject']
    
    # Find teacher
    ts = TeacherSubject.query.filter_by(subject=subject).first()
    if not ts:
        return jsonify({'conflict': False})
    
    # Check conflicts
    conflict = Schedule.query.filter_by(day=day, period=period, teacher_id=ts.teacher_id).filter(
        Schedule.class_name != class_name
    ).first()
    
    if conflict:
        teacher = User.query.filter_by(user_id=ts.teacher_id).first()
        
        # Find alternatives
        occupied = [s.period for s in Schedule.query.filter_by(day=day, teacher_id=ts.teacher_id).all()]
        alternatives = [p for p in range(1, 9) if p not in occupied][:3]
        
        return jsonify({
            'conflict': True,
            'details': [{
                'teacher': teacher.name if teacher else 'Unknown',
                'class': conflict.class_name
            }],
            'alternatives': alternatives
        })
    
    return jsonify({'conflict': False})

# Homework
@app.route('/api/homework', methods=['GET', 'POST', 'DELETE'])
@login_required
@limiter.limit("60 per minute")
def homework_api():
    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        query = Homework.query
        if session['role'] == 'student':
            query = query.filter_by(class_name=session.get('class', ''))
        
        homeworks = query.order_by(Homework.due_date).paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify([{
            'id': h.id,
            'subject': h.subject,
            'title': h.title,
            'description': h.description,
            'date_given': h.date_given.isoformat(),
            'due_date': h.due_date.isoformat(),
            'class': h.class_name
        } for h in homeworks.items])
    
    elif request.method == 'POST':
        data = request.get_json()
        hw_id = f"HW{int(datetime.utcnow().timestamp())}"
        
        homework = Homework(
            id=hw_id,
            subject=sanitize_input(data['subject']),
            title=sanitize_input(data['title']),
            description=sanitize_input(data.get('description', '')),
            date_given=datetime.fromisoformat(data['date_given']),
            due_date=datetime.fromisoformat(data['due_date']),
            class_name=sanitize_input(data['class']),
            created_by=session['user_id']
        )
        db.session.add(homework)
        db.session.commit()
        
        return jsonify({'success': True, 'id': hw_id})
    
