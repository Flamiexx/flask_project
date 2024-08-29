from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Roma100@localhost/users'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_or_not_to_secret_=)'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    __tablename__ = 'users'  # Указываем безопасное имя для таблицы
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    login = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.name}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        login = request.form.get('login')
        email = request.form.get('email')
        password = request.form.get('password')

        if not name or not login or not email or not password:
            flash('All fields are required!', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, login=login, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Login or email already exists.', 'danger')
            return render_template('register.html')

    # Если метод GET, просто отобразить форму регистрации
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')

        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Устанавливаем идентификатор пользователя в сессию
            return redirect(url_for('info'))
        else:
            flash('Invalid login or password.', 'danger')

    return render_template('login.html')


@app.route('/add', methods=['POST'])
def add_user():
    name = request.form.get('name')
    login = request.form.get('login')
    email = request.form.get('email')
    password = request.form.get('password')

    if not all([name, login, email, password]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('index'))

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(name=name, login=login, email=email, password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        flash('Login or email already exists.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while adding the user.', 'danger')
    return redirect(url_for('index'))


@app.route('/info')
def info():
    if 'user_id' not in session:
        flash('You must be logged in to view this page.', 'alert')
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('info.html', users=users)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()

    app.run(debug=False)
