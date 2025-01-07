from app import app, User
from werkzeug.security import generate_password_hash

def init_db():
    # Crear usuario admin si no existe
    try:
        User.objects(username='admin').get()
    except User.DoesNotExist:
        admin = User(
            username='admin',
            password_hash=generate_password_hash('password'),
            is_admin=True
        )
        admin.save()
        print("Usuario admin creado exitosamente!")

if __name__ == '__main__':
    init_db()