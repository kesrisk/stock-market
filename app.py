from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import db, bcrypt, User, Session, UpdateHistory, SessionUser

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sessions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# class User(UserMixin, User):
#     pass

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/create-superuser', methods=['GET', 'POST'])
def create_superuser():
    if not User.query.filter_by(phone_number='superuser').first():
        superuser = User(name='superuser', phone_number='superuser', role='superuser')
        superuser.set_password('shivam')
        db.session.add(superuser)
        db.session.commit()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        user = User(name=name, phone_number=phone_number)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        user = User.query.filter_by(phone_number=phone_number).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid phone number or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    if current_user.role == 'superuser':
        users = User.query.all()
        sessions = Session.query.all()
        return render_template('superuser_home.html', users=users, sessions=sessions)
    else:
        session_users = SessionUser.query.filter_by(user_id=current_user.id).all()
        sessions = [su.session for su in session_users]
        return render_template('home.html', sessions=sessions)

@app.route('/start_session', methods=['POST'])
@login_required
def start_session():
    new_session = Session(creator_id=current_user.id)
    db.session.add(new_session)
    db.session.commit()
    session_user = SessionUser(session_id=new_session.id, user_id=current_user.id, role='editor')
    db.session.add(session_user)
    db.session.commit()
    return redirect(url_for('view_session', session_id=new_session.id))

@app.route('/session/<int:session_id>', methods=['GET', 'POST'])
@login_required
def view_session(session_id):
    session = Session.query.get_or_404(session_id)
    session_user = SessionUser.query.filter_by(session_id=session_id, user_id=current_user.id).first()
    
    if current_user.role != 'superuser' and not session_user:
        flash('You do not have access to this session.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST' and session_user and session_user.role == 'editor':
        field = request.form.get('field')
        value = request.form.get('value')
        if field and value:
            value = int(value)
            old_value = getattr(session, field)
            new_value = max(0, old_value + value)
            change_value = value
            update_history = UpdateHistory(session_id=session.id, field=field, old_value=old_value, new_value=new_value, change_value=change_value)
            db.session.add(update_history)
            setattr(session, field, new_value)
            db.session.commit()
            return redirect(url_for('view_session', session_id=session.id))

    update_history = UpdateHistory.query.filter_by(session_id=session_id).order_by(UpdateHistory.timestamp.desc()).all()
    return render_template('session.html', session=session, update_history=update_history, session_user=session_user)

@app.route('/revert_update/<int:update_id>', methods=['POST'])
@login_required
def revert_update(update_id):
    update = UpdateHistory.query.get_or_404(update_id)
    session = Session.query.get_or_404(update.session_id)
    session_user = SessionUser.query.filter_by(session_id=update.session_id, user_id=current_user.id).first()
    
    if current_user.role != 'superuser' and (not session_user or session_user.role != 'editor'):
        flash('You do not have permission to revert this update.', 'danger')
        return redirect(url_for('home'))
    
    if update:
        setattr(session, update.field, update.old_value)
        update.reverted = True
        revert_comment = f"Reverted change: {update.change_value} to {update.field}"
        revert_history = UpdateHistory(
            session_id=session.id, 
            field=update.field, 
            old_value=update.new_value, 
            new_value=update.old_value, 
            change_value=-update.change_value, 
            revert_comment=revert_comment
        )
        db.session.add(revert_history)
        db.session.commit()
    
    return redirect(url_for('view_session', session_id=update.session_id))

@app.route('/share_session/<int:session_id>', methods=['POST'])
@login_required
def share_session(session_id):
    session = Session.query.get_or_404(session_id)
    session_user = SessionUser.query.filter_by(session_id=session_id, user_id=current_user.id).first()
    
    if current_user.role != 'superuser' and (not session_user or session_user.role != 'editor'):
        flash('You do not have permission to share this session.', 'danger')
        return redirect(url_for('home'))
    
    phone_number = request.form.get('phone_number')
    role = request.form.get('role')
    user = User.query.filter_by(phone_number=phone_number).first()
    if user:
        new_session_user = SessionUser(session_id=session.id, user_id=user.id, role=role)
        db.session.add(new_session_user)
        db.session.commit()
        flash('Session shared successfully.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('view_session', session_id=session.id))

@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role != 'superuser':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/update_user_role/<int:user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'superuser':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role in ['superuser', 'editor', 'viewer']:
        user.role = new_role
        db.session.commit()
        flash('User role updated successfully.', 'success')
    else:
        flash('Invalid role specified.', 'danger')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'superuser':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/remove_user_from_session/<int:session_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_user_from_session(session_id, user_id):
    session = Session.query.get_or_404(session_id)
    session_user = SessionUser.query.filter_by(session_id=session_id, user_id=user_id).first()
    
    if current_user.role != 'superuser' and (not session_user or session_user.role != 'editor'):
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('view_session', session_id=session_id))
    
    if session_user:
        db.session.delete(session_user)
        db.session.commit()
        flash('User removed from session successfully.', 'success')
    else:
        flash('User not found in this session.', 'danger')
    
    return redirect(url_for('view_session', session_id=session_id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
