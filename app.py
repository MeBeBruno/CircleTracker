import os
import re
import uuid
from datetime import date, datetime
from flask import Flask, render_template, redirect, url_for, request, flash, Response, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from icalendar import Calendar, Event
from models import db, User, Cycle, CycleDay, UserSession, ENCRYPTION_KEY
from sensiplan import SensiplanEvaluator

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-prod')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- DATABASE CONFIG ---
# Prüfe, ob wir auf Render sind (dort gibt es die Env-Var DATABASE_URL)
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Render nutzt manchmal noch "postgres://", SQLAlchemy braucht aber "postgresql://"
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Fallback für lokal: SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///circletracker.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- SESSION & SECURITY CHECKS ---
@app.before_request
def check_valid_session():
    # Wenn User eingeloggt ist, prüfe ob Session-Token in DB existiert
    # (So können wir Geräte ausloggen)
    if current_user.is_authenticated:
        token = session.get('device_token')
        if not token:
            logout_user() # Keine valide Session
            return
        
        user_session = UserSession.query.filter_by(session_token=token).first()
        if not user_session:
            logout_user() # Session wurde remote gelöscht
        else:
            # Update last active
            user_session.last_active = datetime.utcnow()
            db.session.commit()

def get_or_create_active_cycle(user):
    cycle = Cycle.query.filter_by(user_id=user.id, is_active=True).first()
    if not cycle:
        cycle = Cycle(user_id=user.id, start_date=date.today())
        db.session.add(cycle)
        db.session.commit()
    return cycle

# --- ROUTES ---

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        handle = request.form.get('handle').lower()
        if not re.match(r'^[a-z][a-z0-9.-]*[a-z0-9]$', handle) or not (3 <= len(handle) <= 16) or '..' in handle:
            flash('Handle ungültig (3-16 Zeichen, a-z0-9.-)', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(handle=handle).first():
            flash('Handle vergeben.', 'error')
            return redirect(url_for('register'))
            
        new_user = User(handle=handle, name=request.form.get('name'), 
                        password_hash=generate_password_hash(request.form.get('password')))
        db.session.add(new_user)
        db.session.commit()
        
        # Direkt einloggen nach Register
        token = str(uuid.uuid4())
        session['device_token'] = token
        new_session = UserSession(user_id=new_user.id, session_token=token, 
                                  user_agent=request.user_agent.string, ip_address=request.remote_addr)
        db.session.add(new_session)
        db.session.commit()
        login_user(new_user)
        
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(handle=request.form.get('handle').lower()).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            # Login erfolgreich -> Session erstellen
            token = str(uuid.uuid4())
            session['device_token'] = token
            new_session = UserSession(user_id=user.id, session_token=token, 
                                      user_agent=request.user_agent.string, ip_address=request.remote_addr)
            db.session.add(new_session)
            db.session.commit()
            
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Falsche Daten.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Aktuelle Session aus DB löschen
    token = session.get('device_token')
    if token:
        UserSession.query.filter_by(session_token=token).delete()
        db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    view_mode = request.args.get('view')
    target_user = current_user.partner if (view_mode == 'partner' and current_user.partner) else current_user
    is_own = (target_user.id == current_user.id)

    cycle = get_or_create_active_cycle(target_user)
    cycle_days = cycle.days.all()
    
    evaluator = SensiplanEvaluator(cycle_days)
    status = evaluator.evaluate()
    
    today = date.today() # <--- Diese Variable haben wir definiert...
    is_safe = (status['safe_from_date'] and today > status['safe_from_date'])

    chart_labels = [d.date.strftime('%d.%m') for d in evaluator.days]
    chart_temps = [d.temperature for d in evaluator.days]

    today_log = CycleDay.query.filter_by(cycle_id=cycle.id, date=today).first()

    return render_template('dashboard.html', 
                           user=target_user, 
                           cycle=cycle, 
                           today_log=today_log,
                           status=status, 
                           is_safe=is_safe, 
                           chart_labels=chart_labels, 
                           chart_temps=chart_temps, 
                           is_own_cycle=is_own,
                           today=today) # <--- WICHTIG: Hier müssen wir sie übergeben!

# --- SETTINGS CENTER ROUTES ---

@app.route('/settings')
@login_required
def settings():
    # Alle Daten laden für die Tabelle
    # Wir laden ALLE CycleDays von allen Zyklen des Users, sortiert nach Datum (neueste zuerst)
    # Join über Cycle table um user_id zu filtern
    all_entries = CycleDay.query.join(Cycle).filter(Cycle.user_id == current_user.id).order_by(CycleDay.date.desc()).all()
    
    # Alle Sessions laden
    sessions = UserSession.query.filter_by(user_id=current_user.id).order_by(UserSession.last_active.desc()).all()
    current_token = session.get('device_token')
    
    return render_template('settings.html', entries=all_entries, sessions=sessions, current_token=current_token)

@app.route('/settings/update_account', methods=['POST'])
@login_required
def update_account():
    new_name = request.form.get('name')
    if new_name:
        current_user.name = new_name
        db.session.commit()
        flash('Name gespeichert.', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/delete_account', methods=['POST'])
@login_required
def delete_account():
    confirm = request.form.get('confirm')
    if confirm == 'DELETE':
        # User und via Cascade alles andere löschen
        db.session.delete(current_user)
        db.session.commit()
        logout_user()
        flash('Dein Account wurde gelöscht. Auf Wiedersehen!', 'success')
        return redirect(url_for('login'))
    flash('Bitte bestätige das Löschen mit "DELETE".', 'error')
    return redirect(url_for('settings'))

@app.route('/settings/revoke_session/<int:session_id>')
@login_required
def revoke_session(session_id):
    s = UserSession.query.get_or_404(session_id)
    if s.user_id == current_user.id:
        db.session.delete(s)
        db.session.commit()
        flash('Gerät ausgeloggt.', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/data/delete_all', methods=['POST'])
@login_required
def delete_all_data():
    confirm = request.form.get('confirm_bulk')
    if confirm == 'WIPE':
        # Lösche alle Zyklen (Cascade löscht Days)
        Cycle.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        flash('Alle Zyklusdaten wurden gelöscht.', 'success')
    else:
        flash('Bestätigung falsch.', 'error')
    return redirect(url_for('settings'))

@app.route('/settings/data/delete/<int:entry_id>')
@login_required
def delete_entry(entry_id):
    entry = CycleDay.query.get_or_404(entry_id)
    # Security Check: Gehört der Eintrag mir?
    if entry.cycle.user_id == current_user.id:
        db.session.delete(entry)
        db.session.commit()
        flash('Eintrag gelöscht.', 'success')
    return redirect(url_for('settings'))

@app.route('/edit_entry/<date_str>', methods=['GET', 'POST'])
@login_required
def edit_entry(date_str):
    # Datum parsen
    try:
        target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except:
        flash('Ungültiges Datum', 'error')
        return redirect(url_for('settings'))

    # Zyklus finden, in den das Datum passt, oder erstellen
    # Einfachheitshalber: Suche Zyklus, der Datum einschließt, oder aktiven Zyklus
    # Wir nehmen "get_or_create_active_cycle" Logik hier manuell, 
    # aber eigentlich müssen wir den richtigen historischen Zyklus finden.
    # Logic: Finde Zyklus where start_date <= date. Sort desc start_date limit 1.
    cycle = Cycle.query.filter(Cycle.user_id==current_user.id, Cycle.start_date <= target_date).order_by(Cycle.start_date.desc()).first()
    
    if not cycle:
        # Fallback: Erstelle neuen Zyklus, wenn keiner da ist (z.B. historischer Eintrag vor erstem Zyklus)
        cycle = Cycle(user_id=current_user.id, start_date=target_date)
        db.session.add(cycle)
        db.session.commit()

    entry = CycleDay.query.filter_by(cycle_id=cycle.id, date=target_date).first()

    if request.method == 'POST':
        if not entry:
            entry = CycleDay(cycle_id=cycle.id, date=target_date)
            db.session.add(entry)
        
        # Speichern (Copy Paste from Add Entry Logic)
        try:
            if request.form.get('temperature'):
                entry.temperature = float(request.form.get('temperature').replace(',', '.'))
            entry.mucus_code = request.form.get('mucus')
            entry.bleeding = request.form.get('bleeding')
            entry.intercourse = (request.form.get('intercourse') == 'on')
            
            entry.cervix_height = request.form.get('cervix_height')
            entry.cervix_openness = request.form.get('cervix_openness')
            entry.cervix_firmness = request.form.get('cervix_firmness')
            entry.test_lh = request.form.get('test_lh')
            entry.test_pregnancy = request.form.get('test_pregnancy')
            entry.libido = request.form.get('libido')
            entry.mood = request.form.get('mood')
            entry.pain_mittelschmerz = (request.form.get('pain_mittelschmerz') == 'on')
            entry.pain_period = (request.form.get('pain_period') == 'on')
            entry.pain_headache = (request.form.get('pain_headache') == 'on')
            entry.breast_symptom = (request.form.get('breast_symptom') == 'on')
            entry.notes = request.form.get('notes')
            
            db.session.commit()
            flash('Eintrag aktualisiert.', 'success')
            return redirect(url_for('settings')) # Zurück zur Liste
        except Exception as e:
            flash(f'Fehler: {str(e)}', 'error')

    return render_template('edit_entry.html', entry=entry, date=target_date)

# --- STANDARD ADD ENTRY (Redirect logic) ---
@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    # Redirectet intern zu edit_entry mit heutigem Datum, um Code zu sparen?
    # Nein, wir nutzen die Logik, aber redirecten zum Dashboard.
    # Der Einfachheit halber lassen wir die Route wie sie war, 
    # aber nutzen edit_entry logic wäre sauberer. 
    # Ich lasse den alten Code hier für Stabilität.
    
    cycle = get_or_create_active_cycle(current_user)
    today = date.today()
    log = CycleDay.query.filter_by(cycle_id=cycle.id, date=today).first()
    if not log:
        log = CycleDay(cycle_id=cycle.id, date=today)
        db.session.add(log)
    
    try:
        if request.form.get('temperature'):
            log.temperature = float(request.form.get('temperature').replace(',', '.'))
        log.mucus_code = request.form.get('mucus')
        log.bleeding = request.form.get('bleeding')
        log.intercourse = (request.form.get('intercourse') == 'on')
        log.cervix_height = request.form.get('cervix_height')
        log.cervix_openness = request.form.get('cervix_openness')
        log.cervix_firmness = request.form.get('cervix_firmness')
        log.test_lh = request.form.get('test_lh')
        log.test_pregnancy = request.form.get('test_pregnancy')
        log.libido = request.form.get('libido')
        log.mood = request.form.get('mood')
        log.pain_mittelschmerz = (request.form.get('pain_mittelschmerz') == 'on')
        log.pain_period = (request.form.get('pain_period') == 'on')
        log.pain_headache = (request.form.get('pain_headache') == 'on')
        log.breast_symptom = (request.form.get('breast_symptom') == 'on')
        log.notes = request.form.get('notes')
        
        db.session.commit()
        flash('Gespeichert!', 'success')
    except Exception as e:
        flash(f'Fehler: {str(e)}', 'error')

    return redirect(url_for('dashboard'))


@app.route('/connect_partner', methods=['POST'])
@login_required
def connect_partner():
    partner = User.query.filter_by(handle=request.form.get('partner_handle').lower()).first()
    if partner and partner.id != current_user.id:
        current_user.partner = partner
        partner.partner = current_user
        db.session.commit()
        flash('Verbunden!', 'success')
    else:
        flash('Partner nicht gefunden.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/ical/<token>.ics')
def ical_feed(token):
    user = User.query.filter_by(ical_token=token).first()
    if not user: return "Invalid Token", 404
    cycle = get_or_create_active_cycle(user) # Nur aktueller Zyklus für Kalender Feed Performance
    evaluator = SensiplanEvaluator(cycle.days.all())
    status = evaluator.evaluate()
    cal = Calendar()
    cal.add('prodid', '-//CircleTracker//mxm.dk//')
    cal.add('version', '2.0')
    cal.add('X-WR-CALNAME', f'CircleTracker: {user.name}')
    for day in evaluator.days:
        if day.bleeding and day.bleeding != 'none':
            event = Event()
            event.add('summary', f'Periode ({day.bleeding})')
            event.add('dtstart', day.date)
            event.add('dtend', day.date)
            cal.add_component(event)
        is_safe_day = (status['safe_from_date'] and day.date > status['safe_from_date'])
        if not is_safe_day:
            event = Event()
            event.add('summary', '⭕ Fruchtbar')
            event.add('dtstart', day.date)
            event.add('dtend', day.date)
            cal.add_component(event)
    return Response(cal.to_ical(), mimetype="text/calendar")

with app.app_context():
    db.create_all()
    print(f"\nENCRYPTION KEY: {ENCRYPTION_KEY}\n")

if __name__ == '__main__':
    app.run(debug=True)