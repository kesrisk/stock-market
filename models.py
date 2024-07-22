from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.schema import UniqueConstraint

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='viewer')
    sessions = db.relationship('SessionUser', back_populates='user', cascade="all, delete-orphan")
    _is_active = db.Column(db.Boolean, nullable=False, default=True)  # Use an underscore

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self._is_active

    @property
    def is_anonymous(self):
        return False

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sbi = db.Column(db.Integer, default=50)
    reliance = db.Column(db.Integer, default=80)
    hdfc = db.Column(db.Integer, default=40)
    infy = db.Column(db.Integer, default=55)
    nifty = db.Column(db.Integer, default=120)
    tata = db.Column(db.Integer, default=35)
    hul = db.Column(db.Integer, default=60)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    users = db.relationship('SessionUser', back_populates='session', cascade="all, delete-orphan")
    update_histories = db.relationship('UpdateHistory', back_populates='session', cascade="all, delete-orphan")

class UpdateHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    field = db.Column(db.String(50), nullable=False)
    old_value = db.Column(db.Integer, nullable=False)
    new_value = db.Column(db.Integer, nullable=False)
    change_value = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    reverted = db.Column(db.Boolean, default=False)
    revert_comment = db.Column(db.String(100), nullable=True)
    session = db.relationship('Session', back_populates='update_histories')

class SessionUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(10), nullable=False)  # 'editor' or 'viewer'
    session = db.relationship('Session', back_populates='users')
    user = db.relationship('User', back_populates='sessions')

    __table_args__ = (UniqueConstraint('session_id', 'user_id', name='unique_session_user'),)