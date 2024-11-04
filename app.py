from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
from functools import wraps
import pyotp
import os
import random
import string
from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('sakih11F', 'dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///tienda.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'
csrf = CSRFProtect(app)

# Modelos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    credit = db.Column(db.Float, default=0.0)
    is_admin = db.Column(db.Boolean, default=False)
    secret_key = db.Column(db.String(32))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.secret_key:
            self.secret_key = pyotp.random_base32()

    def get_totp_code(self):
        if not self.secret_key:
            self.secret_key = pyotp.random_base32()
            db.session.commit()
        totp = pyotp.TOTP(self.secret_key, interval=30)
        return totp.now()

    def verify_totp(self, code):
        if not self.secret_key:
            return False
        totp = pyotp.TOTP(self.secret_key, interval=30)
        return totp.verify(code)

class RedeemCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    used_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)

    @property
    def used_by_user(self):
        return User.query.get(self.used_by) if self.used_by else None

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    features = db.Column(db.Text, nullable=False)
    whatsapp_link = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_code(prefix="TZILG", length=10):
    consonants = 'BCDFGHJKLMNPQRSTVWXYZ'
    numbers = '0123456789'
    allowed_chars = consonants + numbers
    random_part = ''.join(random.choice(allowed_chars) for _ in range(length))
    return f"{prefix}{random_part}"

# Rutas
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya está en uso', 'error')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            credit=0.0,
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registro exitoso. Por favor inicia sesión', 'success')
        return redirect(url_for('user_login'))
    
    return render_template('register.html')

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('verify_2fa'))
        
        flash('Usuario o contraseña incorrectos', 'error')
    return render_template('user_login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    if request.method == 'POST':
        code = request.form.get('code')
        if current_user.verify_totp(code):
            session['verified_2fa'] = True
            next_page = 'admin' if current_user.is_admin else 'user_dashboard'
            return redirect(url_for(next_page))
        flash('Código incorrecto', 'error')
    
    security_code = current_user.get_totp_code()
    return render_template('verify_2fa.html', security_code=security_code)

@app.route('/get-security-code')
@login_required
def get_security_code():
    return jsonify({'code': current_user.get_totp_code()})

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin'))
    return render_template('user_dashboard.html', RedeemCode=RedeemCode)

@app.route('/user/redeem', methods=['POST'])
@login_required
def redeem_code():
    code = request.form.get('code')
    redeem_code = RedeemCode.query.filter_by(code=code, is_used=False).first()
    
    if redeem_code:
        current_user.credit += redeem_code.amount
        redeem_code.is_used = True
        redeem_code.used_by = current_user.id
        redeem_code.used_at = datetime.utcnow()
        db.session.commit()
        flash(f'¡Código canjeado exitosamente! Se han agregado ${redeem_code.amount} a tu cuenta', 'success')
    else:
        flash('Código inválido o ya utilizado', 'error')
    
    return redirect(url_for('user_dashboard'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/admin/codes')
@login_required
def admin_codes():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    codes = RedeemCode.query.order_by(RedeemCode.created_at.desc()).all()
    last_generated_code = request.args.get('last_generated_code')
    return render_template('admin_codes.html', codes=codes, last_generated_code=last_generated_code)

@app.route('/admin/generate_code', methods=['POST'])
@login_required
def generate_code_route():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    try:
        amount = float(request.form.get('amount'))
        if amount <= 0:
            raise ValueError("El monto debe ser positivo")
            
        code = generate_code()
        
        while RedeemCode.query.filter_by(code=code).first():
            code = generate_code()
        
        new_code = RedeemCode(
            code=code,
            amount=amount,
            is_used=False,
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_code)
        db.session.commit()
        
        flash('Código generado exitosamente', 'success')
        return redirect(url_for('admin_codes', last_generated_code=code))
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        flash('Error al generar el código', 'error')
        print(f"Error: {str(e)}")
        
    return redirect(url_for('admin_codes'))

@app.route('/admin/code/delete/<int:id>', methods=['POST'])
@login_required
def delete_code(id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    try:
        code = RedeemCode.query.get_or_404(id)
        if code.is_used:
            flash('No se puede eliminar un código que ya ha sido usado', 'error')
            return redirect(url_for('admin_codes'))
            
        db.session.delete(code)
        db.session.commit()
        flash('Código eliminado exitosamente', 'success')
    except Exception as e:
        flash('Error al eliminar el código', 'error')
        print(f"Error: {str(e)}")
        
    return redirect(url_for('admin_codes'))

@app.route('/product/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            new_product = Product(
                name=request.form.get('name'),
                description=request.form.get('description'),
                price=float(request.form.get('price')),
                features=request.form.get('features'),
                whatsapp_link=request.form.get('whatsapp_link')
            )
            db.session.add(new_product)
            db.session.commit()
            flash('Producto creado exitosamente', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            flash(f'Error al crear el producto: {str(e)}', 'error')
            
    return render_template('edit_product.html', product=None)

@app.route('/product/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    product = Product.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            product.name = request.form.get('name')
            product.description = request.form.get('description')
            product.price = float(request.form.get('price'))
            product.features = request.form.get('features')
            product.whatsapp_link = request.form.get('whatsapp_link')
            
            db.session.commit()
            flash('Producto actualizado exitosamente', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            flash(f'Error al actualizar el producto: {str(e)}', 'error')
            
    return render_template('edit_product.html', product=product)

@app.route('/product/delete/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    try:
        product = Product.query.get_or_404(id)
        db.session.delete(product)
        db.session.commit()
        flash('Producto eliminado exitosamente', 'success')
    except Exception as e:
        flash(f'Error al eliminar el producto: {str(e)}', 'error')
        
    return redirect(url_for('admin'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Has cerrado sesión exitosamente', 'success')
    return redirect(url_for('index'))

def create_initial_products():
    if Product.query.count() == 0:
        products = [
            {
                'name': 'Game Pass Ultimate',
                'description': 'La experiencia Xbox definitiva',
                'price': 299.00,
                'features': 'Xbox Live Gold incluido\n+100 juegos para consola y PC\nEA Play incluido\nJuegos día 1 de lanzamiento',
                'whatsapp_link': 'https://wa.me/tucélular?text=Hola,%20me%20interesa%20Game%20Pass%20Ultimate'
            },
            {
                'name': 'Xbox Live Gold',
                'description': 'Juega en línea con amigos',
                'price': 149.00,
                'features': 'Multijugador en línea\n2-4 juegos gratis al mes\nDescuentos exclusivos',
                'whatsapp_link': 'https://wa.me/tucélular?text=Hola,%20me%20interesa%20Xbox%20Live%20Gold'
            },
            {
                'name': 'Game Pass',
                'description': 'Biblioteca de juegos infinita',
                'price': 229.00,
                'features': '+100 juegos de alta calidad\nNuevos juegos cada mes\nDescuentos exclusivos',
                'whatsapp_link': 'https://wa.me/tucélular?text=Hola,%20me%20interesa%20Game%20Pass'
            }
        ]
        
        for product_data in products:
            product = Product(**product_data)
            db.session.add(product)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            user = User(
                username='admin',
                password_hash=generate_password_hash('password'),
                is_admin=True
            )
            db.session.add(user)
            db.session.commit()
        create_initial_products()
    app.run(debug=True)