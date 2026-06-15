from app import app, db, Role, User, Genre, Book, Cover, Review
from werkzeug.security import generate_password_hash
import datetime

def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()

        # Роли
        roles = [
            Role(name='admin', description='Суперпользователь, полный доступ'),
            Role(name='moderator', description='Может редактировать книги и модерировать рецензии'),
            Role(name='user', description='Может оставлять рецензии')
        ]
        db.session.add_all(roles)
        
        # Пользователи
        users = [
            User(login='admin', password_hash=generate_password_hash('admin'), last_name='Иванов', first_name='Иван', middle_name='Иванович', role_id=1),
            User(login='mod', password_hash=generate_password_hash('mod'), last_name='Петров', first_name='Петр', middle_name='Петрович', role_id=2),
            User(login='user', password_hash=generate_password_hash('user'), last_name='Сидоров', first_name='Сидор', middle_name='Сидорович', role_id=3)
        ]
        db.session.add_all(users)

        # Жанры
        genres = [
            Genre(name='Фантастика'),
            Genre(name='Детектив'),
            Genre(name='Классика')
        ]
        db.session.add_all(genres)
        db.session.commit()
        
        print("База данных успешно инициализирована!")
        print("Логины: admin / mod / user")
        print("Пароли: admin / mod / user")

if __name__ == '__main__':
    init_db()