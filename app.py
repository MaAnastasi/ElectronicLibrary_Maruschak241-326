import os
import hashlib
import datetime
import csv
import io
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import bleach
import markdown
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super_secret_exam_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Для выполнения данного действия необходимо пройти процедуру аутентификации'

# --- МОДЕЛИ ДАННЫХ ---
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)

    @property
    def fio(self):
        middle = f" {self.middle_name}" if self.middle_name else ""
        return f"{self.last_name} {self.first_name}{middle}"

class Genre(db.Model):
    __tablename__ = 'genres'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    publisher = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    pages = db.Column(db.Integer, nullable=False)
    
    cover = db.relationship('Cover', backref='book', uselist=False, cascade="all, delete-orphan")
    genres = db.relationship('Genre', secondary='book_genres', backref='books')
    reviews = db.relationship('Review', backref='book', cascade="all, delete-orphan")
    visits = db.relationship('Visit', backref='book', cascade="all, delete-orphan")

class BookGenre(db.Model):
    __tablename__ = 'book_genres'
    book_id = db.Column(db.Integer, db.ForeignKey('books.id', ondelete='CASCADE'), primary_key=True)
    genre_id = db.Column(db.Integer, db.ForeignKey('genres.id', ondelete='CASCADE'), primary_key=True)

class Cover(db.Model):
    __tablename__ = 'covers'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(50), nullable=False)
    md5_hash = db.Column(db.String(32), unique=True, nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id', ondelete='CASCADE'), nullable=False)

class Review(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user = db.relationship('User', backref='reviews')

class Visit(db.Model):
    __tablename__ = 'visits'
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    session_id = db.Column(db.String(100), nullable=True) # Для неаутентифицированных
    visited_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_session_id():
    if 'session_id' not in session:
        session['session_id'] = hashlib.md5(os.urandom(16)).hexdigest()
    return session['session_id']

def require_role(role_name):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Для выполнения данного действия необходимо пройти процедуру аутентификации', 'danger')
                return redirect(url_for('login', next=request.url))
            if current_user.role.name != role_name and role_name != 'any':
                if role_name == 'admin' and current_user.role.name != 'admin':
                    flash('У вас недостаточно прав для выполнения данного действия', 'danger')
                    return redirect(url_for('index'))
                if role_name == 'moderator' and current_user.role.name not in ['admin', 'moderator']:
                    flash('У вас недостаточно прав для выполнения данного действия', 'danger')
                    return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapped_function
    return decorator

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def sanitize_html(text):
    # Преобразуем frozenset в list перед сложением
    allowed_tags = list(bleach.sanitizer.ALLOWED_TAGS) + ['p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'strong', 'em', 'a']
    return bleach.clean(text, tags=allowed_tags, attributes={'a': ['href', 'title']})

# --- МАРШРУТЫ ---
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    pagination = Book.query.order_by(Book.year.desc()).paginate(page=page, per_page=10, error_out=False)
    
    # Вариант 4: Популярные книги (за последние 3 месяца)
    three_months_ago = datetime.datetime.utcnow() - datetime.timedelta(days=90)
    popular_books = db.session.query(Book, db.func.count(Visit.id).label('visit_count'))\
        .join(Visit, Book.id == Visit.book_id)\
        .filter(Visit.visited_at >= three_months_ago)\
        .group_by(Book.id)\
        .order_by(db.desc('visit_count'))\
        .limit(5).all()

    # Вариант 4: Недавно просмотренные
    recent_visits = []
    if current_user.is_authenticated:
        recent_visits = Visit.query.filter_by(user_id=current_user.id)\
            .order_by(Visit.visited_at.desc()).limit(5).all()
    else:
        recent_visits = Visit.query.filter_by(session_id=get_session_id())\
            .order_by(Visit.visited_at.desc()).limit(5).all()
            
    recent_books = [Visit.query.get(v.id).book for v in recent_visits] # Упрощенно, лучше через join

    return render_template('index.html', pagination=pagination, popular_books=popular_books, recent_books=recent_books)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        login_str = request.form.get('login')
        password = request.form.get('password')
        user = User.query.filter_by(login=login_str).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=request.form.get('remember'))
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        flash('Невозможно аутентифицироваться с указанными логином и паролем', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы', 'info')
    return redirect(request.args.get('next', url_for('index')))

@app.route('/book/add', methods=['GET', 'POST'])
@require_role('admin')
def add_book():
    genres = Genre.query.all()
    if request.method == 'POST':
        try:
            # 1. Сохраняем книгу, чтобы получить ID
            desc_raw = request.form.get('description')
            new_book = Book(
                title=request.form.get('title'),
                description=sanitize_html(desc_raw), # Санитайзер
                year=int(request.form.get('year')),
                publisher=request.form.get('publisher'),
                author=request.form.get('author'),
                pages=int(request.form.get('pages'))
            )
            db.session.add(new_book)
            db.session.flush() # Получаем new_book.id, но не коммитим

            # 2. Обработка жанров
            genre_ids = request.form.getlist('genres')
            for gid in genre_ids:
                new_book.genres.append(Genre.query.get(gid))

            # 3. Обработка обложки
            cover_file = request.files.get('cover')
            if cover_file and cover_file.filename != '':
                # Сохраняем временно для расчета хэша
                temp_filename = secure_filename(cover_file.filename)
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + temp_filename)
                cover_file.save(temp_path)
                file_hash = calculate_md5(temp_path)
                
                existing_cover = Cover.query.filter_by(md5_hash=file_hash).first()
                if existing_cover:
                    new_book.cover = existing_cover
                    os.remove(temp_path)
                else:
                    new_filename = f"{new_book.id}_{temp_filename}"
                    final_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    os.rename(temp_path, final_path)
                    
                    new_cover = Cover(
                        filename=new_filename,
                        mime_type=cover_file.mimetype,
                        md5_hash=file_hash,
                        book_id=new_book.id
                    )
                    db.session.add(new_cover)

            db.session.commit()
            flash('Книга успешно добавлена', 'success')
            return redirect(url_for('view_book', book_id=new_book.id))
            
        except Exception as e:
            db.session.rollback()
            # ВАЖНО: Выводим реальную ошибку в консоль и на экран
            print(f"!!! ОШИБКА ПРИ СОХРАНЕНИИ КНИГИ: {e}") 
            flash(f'При сохранении данных возникла ошибка: {e}', 'danger')
            
            form_data = {
                'title': request.form.get('title', ''),
                'author': request.form.get('author', ''),
                'year': request.form.get('year', ''),
                'publisher': request.form.get('publisher', ''),
                'pages': request.form.get('pages', ''),
                'description': request.form.get('description', ''),
                'genres': request.form.getlist('genres')
            }
            return render_template('book_form.html', genres=genres, is_edit=False, data=form_data, book=None)
            
    # При обычном GET-запросе передаем пустые значения
    return render_template('book_form.html', genres=genres, is_edit=False, data=None, book=None)

@app.route('/book/<int:book_id>/delete', methods=['POST'])
@require_role('admin')
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    try:
        # Удаляем файл обложки, если он есть и не используется другими книгами (по ТЗ удаляем файл удаляемой книги)
        if book.cover:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], book.cover.filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        db.session.delete(book)
        db.session.commit()
        flash('Книга успешно удалена', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении книги', 'danger')
    return redirect(url_for('index'))

@app.route('/book/<int:book_id>')
def view_book(book_id):
    book = Book.query.get_or_404(book_id)
    
    # Вариант 4: Учет посещений (макс 10 в день на пользователя/сессию)
    today_start = datetime.datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + datetime.timedelta(days=1)
    
    user_id = current_user.id if current_user.is_authenticated else None
    session_id = get_session_id() if not current_user.is_authenticated else None
    
    visit_count_today = Visit.query.filter(
        Visit.book_id == book_id,
        Visit.visited_at >= today_start,
        Visit.visited_at < today_end,
        (Visit.user_id == user_id) | (Visit.session_id == session_id)
    ).count()
    
    if visit_count_today < 10:
        new_visit = Visit(book_id=book_id, user_id=user_id, session_id=session_id)
        db.session.add(new_visit)
        db.session.commit()

    # Проверка, оставлял ли пользователь рецензию
    user_review = None
    if current_user.is_authenticated:
        user_review = Review.query.filter_by(book_id=book_id, user_id=current_user.id).first()

    # Преобразование Markdown в HTML для отображения
    description_html = markdown.markdown(book.description)
    
    return render_template('book_view.html', book=book, description_html=description_html, user_review=user_review)

@app.route('/book/<int:book_id>/edit', methods=['GET', 'POST'])
@require_role('moderator')
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    genres = Genre.query.all()
    if request.method == 'POST':
        try:
            book.title = request.form.get('title')
            book.description = sanitize_html(request.form.get('description'))
            book.year = int(request.form.get('year'))
            book.publisher = request.form.get('publisher')
            book.author = request.form.get('author')
            book.pages = int(request.form.get('pages'))
            
            book.genres = []
            for gid in request.form.getlist('genres'):
                book.genres.append(Genre.query.get(gid))
                
            db.session.commit()
            flash('Книга успешно обновлена', 'success')
            return redirect(url_for('view_book', book_id=book.id))
        except Exception as e:
            db.session.rollback()
            print(f"!!! ОШИБКА ПРИ РЕДАКТИРОВАНИИ КНИГИ: {e}")
            flash(f'При сохранении данных возникла ошибка: {e}', 'danger')
            
    return render_template('book_form.html', genres=genres, is_edit=True, book=book)

@app.route('/book/<int:book_id>/review', methods=['GET', 'POST'])
@login_required
def add_review(book_id):
    book = Book.query.get_or_404(book_id)
    if Review.query.filter_by(book_id=book_id, user_id=current_user.id).first():
        flash('Вы уже оставляли рецензию на эту книгу', 'warning')
        return redirect(url_for('view_book', book_id=book_id))

    if request.method == 'POST':
        try:
            raw_text = request.form.get('text')
            review = Review(
                book_id=book_id,
                user_id=current_user.id,
                rating=int(request.form.get('rating')),
                text=sanitize_html(raw_text)
            )
            db.session.add(review)
            db.session.commit()
            flash('Рецензия успешно добавлена', 'success')
            return redirect(url_for('view_book', book_id=book_id))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при сохранении рецензии', 'danger')
            
    return render_template('review_form.html', book=book)

# --- ВАРИАНТ 4: СТАТИСТИКА ---
@app.route('/stats')
@require_role('admin')
def stats():
    tab = request.args.get('tab', 'log')
    page = request.args.get('page', 1, type=int)
    
    # Журнал действий
    log_pagination = db.session.query(Visit, User, Book)\
        .outerjoin(User, Visit.user_id == User.id)\
        .join(Book, Visit.book_id == Book.id)\
        .order_by(Visit.visited_at.desc())\
        .paginate(page=page, per_page=10, error_out=False)
        
    # Статистика просмотров (только аутентифицированные)
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    query = db.session.query(Book, db.func.count(Visit.id).label('views'))\
        .join(Visit, Book.id == Visit.book_id)\
        .filter(Visit.user_id.isnot(None)) # Только авторизованные
        
    if date_from:
        query = query.filter(Visit.visited_at >= datetime.datetime.strptime(date_from, '%Y-%m-%d'))
    if date_to:
        # Добавляем 1 день, чтобы включить весь последний день
        dt_to = datetime.datetime.strptime(date_to, '%Y-%m-%d') + datetime.timedelta(days=1)
        query = query.filter(Visit.visited_at < dt_to)
        
    stats_pagination = query.group_by(Book.id).order_by(db.desc('views')).paginate(page=page, per_page=10, error_out=False)

    return render_template('stats.html', tab=tab, log_pagination=log_pagination, stats_pagination=stats_pagination, date_from=date_from, date_to=date_to)

@app.route('/stats/export/<string:export_type>')
@require_role('admin')
def export_csv(export_type):
    si = io.StringIO()
    cw = csv.writer(si)
    
    if export_type == 'log':
        cw.writerow(['№', 'Пользователь', 'Книга', 'Дата и время'])
        visits = db.session.query(Visit, User, Book)\
            .outerjoin(User, Visit.user_id == User.id)\
            .join(Book, Visit.book_id == Book.id)\
            .order_by(Visit.visited_at.desc()).all()
        for i, (v, u, b) in enumerate(visits, 1):
            user_name = u.fio if u else 'Неаутентифицированный пользователь'
            cw.writerow([i, user_name, b.title, v.visited_at.strftime('%Y-%m-%d %H:%M:%S')])
        filename = f"user_actions_log_{datetime.datetime.utcnow().strftime('%Y%m%d')}.csv"
    else:
        cw.writerow(['№', 'Книга', 'Количество просмотров'])
        stats = db.session.query(Book, db.func.count(Visit.id).label('views'))\
            .join(Visit, Book.id == Visit.book_id)\
            .filter(Visit.user_id.isnot(None))\
            .group_by(Book.id).order_by(db.desc('views')).all()
        for i, (b, count) in enumerate(stats, 1):
            cw.writerow([i, b.title, count])
        filename = f"book_views_stats_{datetime.datetime.utcnow().strftime('%Y%m%d')}.csv"

    output = si.getvalue()
    return send_file(
        io.BytesIO(output.encode('utf-8-sig')), # utf-8-sig для корректного открытия в Excel
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

if __name__ == '__main__':
    app.run(debug=True)