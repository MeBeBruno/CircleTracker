import os
import uuid
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from cryptography.fernet import Fernet

db = SQLAlchemy()

# --- VERSCHLÜSSELUNG ---
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode())
cipher_suite = Fernet(ENCRYPTION_KEY.encode())

def encrypt_value(value):
    if value is None: return None
    return cipher_suite.encrypt(str(value).encode()).decode()

def decrypt_value(token, type_cast=str):
    if token is None: return None
    try:
        decrypted_str = cipher_suite.decrypt(token.encode()).decode()
        if type_cast == bool: return decrypted_str == 'True'
        if type_cast == int: return int(decrypted_str)
        return type_cast(decrypted_str)
    except: return None

# --- MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    handle = db.Column(db.String(16), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    
    ical_token = db.Column(db.String(64), unique=True, default=lambda: str(uuid.uuid4()))

    partner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    partner = db.relationship('User', remote_side=[id], post_update=True)
    
    cycles = db.relationship('Cycle', backref='user', lazy=True, cascade="all, delete-orphan")
    sessions = db.relationship('UserSession', backref='user', lazy=True, cascade="all, delete-orphan")

class UserSession(db.Model):
    """Speichert aktive Logins um Geräte zu verwalten"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(64), unique=True, nullable=False)
    user_agent = db.Column(db.String(255)) # Browser/Gerät Info
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

class Cycle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    days = db.relationship('CycleDay', backref='cycle', lazy='dynamic', cascade="all, delete-orphan")

class CycleDay(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cycle_id = db.Column(db.Integer, db.ForeignKey('cycle.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    
    # Basis (Verschlüsselt)
    _temperature = db.Column("temperature", db.String(500))
    _mucus_code = db.Column("mucus_code", db.String(500)) 
    _bleeding = db.Column("bleeding", db.String(500)) 
    _intercourse = db.Column("intercourse", db.String(500)) 
    
    # Zervix
    _cervix_height = db.Column("cervix_height", db.String(500))
    _cervix_openness = db.Column("cervix_openness", db.String(500)) 
    _cervix_firmness = db.Column("cervix_firmness", db.String(500)) 
    
    # Tests
    _test_lh = db.Column("test_lh", db.String(500)) 
    _test_pregnancy = db.Column("test_pregnancy", db.String(500)) 

    # Symptome
    _libido = db.Column("libido", db.String(500)) 
    _pain_mittelschmerz = db.Column("pain_mittelschmerz", db.String(500)) 
    _pain_period = db.Column("pain_period", db.String(500)) 
    _pain_headache = db.Column("pain_headache", db.String(500)) 
    _breast_symptom = db.Column("breast_symptom", db.String(500)) 
    _mood = db.Column("mood", db.String(500)) 
    
    _notes = db.Column("notes", db.Text)
    
    exclude_temp = db.Column(db.Boolean, default=False)

    # --- Properties ---
    @property
    def temperature(self): return decrypt_value(self._temperature, float)
    @temperature.setter
    def temperature(self, v): self._temperature = encrypt_value(v)

    @property
    def mucus_code(self): return decrypt_value(self._mucus_code, str)
    @mucus_code.setter
    def mucus_code(self, v): self._mucus_code = encrypt_value(v)

    @property
    def bleeding(self): return decrypt_value(self._bleeding, str)
    @bleeding.setter
    def bleeding(self, v): self._bleeding = encrypt_value(v)

    @property
    def intercourse(self): return decrypt_value(self._intercourse, bool)
    @intercourse.setter
    def intercourse(self, v): self._intercourse = encrypt_value(str(v))

    @property
    def cervix_height(self): return decrypt_value(self._cervix_height, str)
    @cervix_height.setter
    def cervix_height(self, v): self._cervix_height = encrypt_value(v)

    @property
    def cervix_openness(self): return decrypt_value(self._cervix_openness, str)
    @cervix_openness.setter
    def cervix_openness(self, v): self._cervix_openness = encrypt_value(v)

    @property
    def cervix_firmness(self): return decrypt_value(self._cervix_firmness, str)
    @cervix_firmness.setter
    def cervix_firmness(self, v): self._cervix_firmness = encrypt_value(v)

    @property
    def test_lh(self): return decrypt_value(self._test_lh, str)
    @test_lh.setter
    def test_lh(self, v): self._test_lh = encrypt_value(v)

    @property
    def test_pregnancy(self): return decrypt_value(self._test_pregnancy, str)
    @test_pregnancy.setter
    def test_pregnancy(self, v): self._test_pregnancy = encrypt_value(v)

    @property
    def libido(self): return decrypt_value(self._libido, str)
    @libido.setter
    def libido(self, v): self._libido = encrypt_value(v)

    @property
    def pain_mittelschmerz(self): return decrypt_value(self._pain_mittelschmerz, bool)
    @pain_mittelschmerz.setter
    def pain_mittelschmerz(self, v): self._pain_mittelschmerz = encrypt_value(str(v))

    @property
    def pain_period(self): return decrypt_value(self._pain_period, bool)
    @pain_period.setter
    def pain_period(self, v): self._pain_period = encrypt_value(str(v))

    @property
    def pain_headache(self): return decrypt_value(self._pain_headache, bool)
    @pain_headache.setter
    def pain_headache(self, v): self._pain_headache = encrypt_value(str(v))

    @property
    def breast_symptom(self): return decrypt_value(self._breast_symptom, bool)
    @breast_symptom.setter
    def breast_symptom(self, v): self._breast_symptom = encrypt_value(str(v))

    @property
    def mood(self): return decrypt_value(self._mood, str)
    @mood.setter
    def mood(self, v): self._mood = encrypt_value(v)

    @property
    def notes(self): return decrypt_value(self._notes, str)
    @notes.setter
    def notes(self, v): self._notes = encrypt_value(v)

    __table_args__ = (db.UniqueConstraint('cycle_id', 'date', name='_cycle_date_uc'),)