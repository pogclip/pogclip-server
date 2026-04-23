# ============================================================
#  PogClip — Web Server  (server.py)
#  Now using PostgreSQL via Supabase!
# ============================================================

from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import os
import secrets
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# ── Security settings ──
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

# ── Database — uses PostgreSQL on Vercel, SQLite locally ──
database_url = os.getenv('DATABASE_URL', 'sqlite:///pogclip.db')
# Fix for SQLAlchemy — postgres:// needs to be postgresql://
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ── Twitch OAuth ──
TWITCH_CLIENT_ID     = os.getenv('TWITCH_CLIENT_ID', '')
TWITCH_CLIENT_SECRET = os.getenv('TWITCH_CLIENT_SECRET', '')
TWITCH_REDIRECT_URI  = os.getenv('TWITCH_REDIRECT_URI', 'https://pogclip-server.vercel.app/auth/twitch/callback')
TWITCH_SCOPES        = 'user:read:email chat:read'

# ── Initialize extensions ──
db            = SQLAlchemy(app)
bcrypt        = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ============================================================
#  DATABASE MODELS
# ============================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id                = db.Column(db.Integer, primary_key=True)
    username          = db.Column(db.String(80), unique=True, nullable=False)
    email             = db.Column(db.String(120), unique=True, nullable=False)
    password_hash     = db.Column(db.String(256))
    plan              = db.Column(db.String(20), default='free')
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)
    twitch_id         = db.Column(db.String(50), unique=True)
    twitch_username   = db.Column(db.String(80))
    twitch_token      = db.Column(db.String(500))
    kick_username     = db.Column(db.String(80))
    tiktok_connected  = db.Column(db.Boolean, default=False)
    youtube_connected = db.Column(db.Boolean, default=False)
    clip_style        = db.Column(db.String(50), default='hype_moment')
    caption_style     = db.Column(db.String(50), default='slam')
    api_key           = db.Column(db.String(64), unique=True)
    clips = db.relationship('Clip', backref='user', lazy=True)


class Clip(db.Model):
    __tablename__ = 'clips'
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    clip_id     = db.Column(db.String(64), unique=True, nullable=False)
    template    = db.Column(db.String(50))
    platform    = db.Column(db.String(50))
    score       = db.Column(db.Float)
    url         = db.Column(db.String(500))
    s3_key      = db.Column(db.String(500))
    views       = db.Column(db.Integer, default=0)
    likes       = db.Column(db.Integer, default=0)
    posted      = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':         self.clip_id,
            'template':   self.template,
            'platform':   self.platform,
            'score':      self.score,
            'url':        self.url,
            'views':      self.views,
            'likes':      self.likes,
            'posted':     self.posted,
            'created_at': self.created_at.isoformat(),
        }


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create tables automatically
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"DB init error: {e}")


# ============================================================
#  PUBLIC ROUTES
# ============================================================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if '@' not in email:
            errors.append('Please enter a valid email.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            return render_template('signup.html', errors=errors,
                                   username=username, email=email)

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        api_key   = secrets.token_hex(32)
        user = User(
            username=username,
            email=email,
            password_hash=hashed_pw,
            api_key=api_key,
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('onboarding'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()
        if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            return redirect(request.args.get('next') or url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid email or password.', email=email)

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# ============================================================
#  TWITCH OAUTH
# ============================================================

@app.route('/auth/twitch')
def auth_twitch():
    state = secrets.token_hex(16)
    session['twitch_oauth_state'] = state
    twitch_auth_url = (
        f"https://id.twitch.tv/oauth2/authorize"
        f"?client_id={TWITCH_CLIENT_ID}"
        f"&redirect_uri={TWITCH_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={TWITCH_SCOPES}"
        f"&state={state}"
    )
    return redirect(twitch_auth_url)


@app.route('/auth/twitch/callback')
def auth_twitch_callback():
    error = request.args.get('error')
    if error:
        return redirect(url_for('dashboard') + '?error=twitch_denied')

    state          = request.args.get('state')
    expected_state = session.pop('twitch_oauth_state', None)
    if not state or state != expected_state:
        return redirect(url_for('dashboard') + '?error=invalid_state')

    code = request.args.get('code')
    token_response = requests.post('https://id.twitch.tv/oauth2/token', data={
        'client_id':     TWITCH_CLIENT_ID,
        'client_secret': TWITCH_CLIENT_SECRET,
        'code':          code,
        'grant_type':    'authorization_code',
        'redirect_uri':  TWITCH_REDIRECT_URI,
    })

    if token_response.status_code != 200:
        return redirect(url_for('dashboard') + '?error=token_failed')

    token_data   = token_response.json()
    access_token = token_data.get('access_token')

    user_response = requests.get('https://api.twitch.tv/helix/users', headers={
        'Authorization': f'Bearer {access_token}',
        'Client-Id':     TWITCH_CLIENT_ID,
    })

    if user_response.status_code != 200:
        return redirect(url_for('dashboard') + '?error=user_fetch_failed')

    twitch_user     = user_response.json()['data'][0]
    twitch_id       = twitch_user['id']
    twitch_username = twitch_user['login']
    twitch_email    = twitch_user.get('email', '')

    if current_user.is_authenticated:
        current_user.twitch_id       = twitch_id
        current_user.twitch_username = twitch_username
        current_user.twitch_token    = access_token
        db.session.commit()
        return redirect(url_for('dashboard') + '?connected=twitch')

    existing = User.query.filter_by(twitch_id=twitch_id).first()
    if existing:
        existing.twitch_token = access_token
        db.session.commit()
        login_user(existing)
        return redirect(url_for('dashboard'))

    base_username = twitch_username
    username      = base_username
    counter       = 1
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1

    email = twitch_email or f"{twitch_id}@twitch.pogclip"
    if User.query.filter_by(email=email).first():
        email = f"{twitch_id}.{secrets.token_hex(4)}@twitch.pogclip"

    new_user = User(
        username=username,
        email=email,
        twitch_id=twitch_id,
        twitch_username=twitch_username,
        twitch_token=access_token,
        api_key=secrets.token_hex(32),
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    return redirect(url_for('onboarding'))


# ============================================================
#  PROTECTED ROUTES
# ============================================================

@app.route('/onboarding')
@login_required
def onboarding():
    return render_template('onboarding.html', user=current_user)


@app.route('/dashboard')
@login_required
def dashboard():
    clips     = Clip.query.filter_by(user_id=current_user.id)\
                          .order_by(Clip.created_at.desc())\
                          .limit(20).all()
    connected = request.args.get('connected')
    error     = request.args.get('error')
    return render_template('dashboard.html',
                           user=current_user,
                           clips=clips,
                           connected=connected,
                           error=error)


@app.route('/download')
@login_required
def download():
    return render_template('download.html',
                           user=current_user,
                           api_key=current_user.api_key)


# ============================================================
#  API ROUTES
# ============================================================

def verify_api_key(api_key):
    return User.query.filter_by(api_key=api_key).first()


@app.route('/api/verify', methods=['POST'])
def api_verify():
    data    = request.get_json()
    api_key = data.get('api_key', '')
    user    = verify_api_key(api_key)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid API key'}), 401
    return jsonify({
        'success':       True,
        'username':      user.username,
        'plan':          user.plan,
        'clip_style':    user.clip_style,
        'caption_style': user.caption_style,
        'twitch':        user.twitch_username,
        'kick':          user.kick_username,
    })


@app.route('/api/clips', methods=['POST'])
def api_save_clip():
    data    = request.get_json()
    api_key = data.get('api_key', '')
    user    = verify_api_key(api_key)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid API key'}), 401

    if user.plan == 'free':
        today_clips = Clip.query.filter_by(user_id=user.id).filter(
            Clip.created_at >= datetime.utcnow().replace(hour=0, minute=0)
        ).count()
        if today_clips >= 3:
            return jsonify({'success': False, 'error': 'Free plan limit reached'}), 403

    clip = Clip(
        user_id  = user.id,
        clip_id  = data.get('clip_id'),
        template = data.get('template'),
        platform = data.get('platform'),
        score    = data.get('score'),
        url      = data.get('url'),
        s3_key   = data.get('s3_key'),
    )
    db.session.add(clip)
    db.session.commit()
    return jsonify({'success': True, 'clip_id': clip.clip_id})


@app.route('/api/clips/<clip_id>/post', methods=['POST'])
@login_required
def api_post_clip(clip_id):
    clip = Clip.query.filter_by(clip_id=clip_id, user_id=current_user.id).first_or_404()
    clip.posted = True
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/clips/<clip_id>', methods=['DELETE'])
@login_required
def api_delete_clip(clip_id):
    clip = Clip.query.filter_by(clip_id=clip_id, user_id=current_user.id).first_or_404()
    db.session.delete(clip)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/settings', methods=['POST'])
@login_required
def api_save_settings():
    data = request.get_json()
    if 'twitch_username' in data:
        current_user.twitch_username = data['twitch_username']
    if 'kick_username' in data:
        current_user.kick_username = data['kick_username']
    if 'clip_style' in data:
        current_user.clip_style = data['clip_style']
    if 'tiktok_connected' in data:
        current_user.tiktok_connected = data['tiktok_connected']
    if 'youtube_connected' in data:
        current_user.youtube_connected = data['youtube_connected']
    db.session.commit()
    return jsonify({'success': True})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
