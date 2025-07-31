from flask import Blueprint, render_template, redirect, url_for, flash, request
from app import db, bcrypt
from app.utils import generate_salt, derive_key, encrypt_password, decrypt_password
from app.models import User, Credential
from app.forms import RegisterForm, LoginForm, CredentialForm, ImportForm
from flask_login import login_user, logout_user, login_required, current_user
import json
from flask import send_file
from io import BytesIO
from cryptography.fernet import Fernet
from flask import session
from app import csrf

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return redirect(url_for('main.login'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        salt = generate_salt()
        user = User(email=form.email.data, password=hashed, salt=salt)
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('main.login'))

    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login failed. Check credentials.', 'danger')
    return render_template('login.html', form=form)

"""@main.route('/2fa_callback')
def twofa_callback():
    result = request.args.get('2fa')
    email = session.pop('pending_2fa', None)

    if result == 'success' and email:
        user = User.query.filter_by(email=email).first()
        if user:
            login_user(user)
            flash("2FA verified. Logged in!", "success")
            return redirect(url_for('main.dashboard'))
    flash("2FA failed or cancelled.", "danger")
    return redirect(url_for('main.login'))
csrf.exempt(twofa_callback)
"""

@main.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = CredentialForm()
    import_form = ImportForm()
    key = derive_key(current_user.password, current_user.salt)

    if form.validate_on_submit():
        encrypted_pw = encrypt_password(form.password.data, key)
        cred = Credential(
            site=form.site.data,
            username=form.username.data,
            password_encrypted=encrypted_pw,
            owner=current_user
        )
        db.session.add(cred)
        db.session.commit()
        flash('Credential saved!', 'success')
        return redirect(url_for('main.dashboard'))

    credentials = Credential.query.filter_by(user_id=current_user.id).all()
    decrypted = [
    {
        'id': c.id,
        'site': c.site,
        'username': c.username,
        'password': decrypt_password(c.password_encrypted, key)
    } for c in credentials
    ]

    return render_template('dashboard.html', form=form, credentials=decrypted, import_form=import_form)


@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_credential(id):
    cred = Credential.query.get_or_404(id)
    if cred.owner != current_user:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('main.dashboard'))

    form = CredentialForm()

    key = derive_key(current_user.password, current_user.salt)

    if form.validate_on_submit():
        cred.site = form.site.data
        cred.username = form.username.data
        cred.password_encrypted = encrypt_password(form.password.data, key)
        db.session.commit()
        flash('Credential updated!', 'success')
        return redirect(url_for('main.dashboard'))

    # Pre-fill form
    form.site.data = cred.site
    form.username.data = cred.username
    form.password.data = decrypt_password(cred.password_encrypted, key)

    return render_template('edit.html', form=form)

@main.route('/delete/<int:id>')
@login_required
def delete_credential(id):
    cred = Credential.query.get_or_404(id)
    if cred.owner != current_user:
        flash("Unauthorized access!", "danger")
        return redirect(url_for('main.dashboard'))

    db.session.delete(cred)
    db.session.commit()
    flash('Credential deleted!', 'info')
    return redirect(url_for('main.dashboard'))

@main.route('/export')
@login_required
def export_credentials():
    key = derive_key(current_user.password, current_user.salt)

    credentials = Credential.query.filter_by(owner=current_user).all()
    exported_data = []

    for cred in credentials:
        decrypted_pw = decrypt_password(cred.password_encrypted, key)
        exported_data.append({
            'site': cred.site,
            'username': cred.username,
            'password': decrypted_pw
        })

    raw_json = json.dumps(exported_data).encode()

    export_key = Fernet.generate_key()
    fernet = Fernet(export_key)
    encrypted_blob = fernet.encrypt(raw_json)

    session['export_key'] = export_key.decode()

    return send_file(
    BytesIO(encrypted_blob),
    download_name='credentials.enc',
    as_attachment=True,
    mimetype='application/octet-stream'
    )

@main.route('/import', methods=['POST'])
@login_required
def import_credentials():
    from app.forms import ImportForm  # optional, if not already imported

    form = ImportForm()
    if not form.validate_on_submit():
        flash("Invalid form submission.", "danger")
        return redirect(url_for('main.dashboard'))

    file = form.file.data
    key = derive_key(current_user.password, current_user.salt)

    try:
        encrypted_data = file.read()
        decrypted_json = decrypt_password(encrypted_data, key)
        creds = json.loads(decrypted_json)

        for c in creds:
            new_cred = Credential(
                site=c['site'],
                username=c['username'],
                password_encrypted=encrypt_password(c['password'], key),
                owner=current_user
            )
            db.session.add(new_cred)

        db.session.commit()
        flash("Credentials imported!", "success")

    except Exception as e:
        flash(f"Import failed: {str(e)}", "danger")

    return redirect(url_for('main.dashboard'))

@main.route('/export_key')
@login_required
def export_key():
    key = session.pop('export_key', None)
    if not key:
        flash("No export key found. Please re-export your credentials.", "warning")
        return redirect(url_for('main.dashboard'))
    return render_template('export_key.html', key=key)



"""
@main.route('/login-success')
def login_success():
    result = request.args.get("2fa")
    username = request.args.get("user")

    if result != "true" or not username:
        flash("2FA verification failed.", "danger")
        return redirect(url_for("main.login"))

    # Lookup the user and log them in
    user = User.query.filter_by(email=username).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.login"))

    login_user(user)
    flash("Logged in successfully with 2FA!", "success")
    return redirect(url_for("main.dashboard"))
"""