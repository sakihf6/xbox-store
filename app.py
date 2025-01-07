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
from datetime import datetime, timedelta

app = Flask(__name__)
@app.before_first_request
def create_tables():
    db.create_all()

database_url = os.environ.get('DATABASE_URL', "postgresql://xbox_m4o1_user:rRieocXzonRdTslrkyDRfgrPp5a1Sc02@dpg-ctuphf56l47c738nk2h0-a.oregon-postgres.render.com/xbox_m4o1")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('sakih11F', 'dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
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
    price = db.Column(db.Float, nullable=False)
    features = db.Column(db.Text, nullable=False)
    expiration_date = db.Column(db.DateTime, nullable=True)

    def get_time_remaining(self):
        if not self.expiration_date:
            return "No expira"
        
        now = datetime.now()
        diff = self.expiration_date - now
        
        if diff.days <= 0:
            return "Expirado"
        
        months = diff.days // 30
        remaining_days = diff.days % 30
        
        # Construir el string de tiempo restante
        time_parts = []
        if months > 0:
            time_parts.append(f"{months} {'mes' if months == 1 else 'meses'}")
        if remaining_days > 0:
            time_parts.append(f"{remaining_days} {'día' if remaining_days == 1 else 'días'}")
        
        if time_parts:
            return "Tiempo restante: " + " y ".join(time_parts)
        else:
            return "Expirado"

class Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    regular_price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(500))
    whatsapp_link = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('CartItem', backref='cart', lazy=True, cascade='all, delete-orphan')
    
    @property
    def total(self):
        return sum(item.subtotal for item in self.items)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    product = db.relationship('Product')
    
    @property
    def subtotal(self):
        return self.product.price * self.quantity

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payment_details = db.Column(db.Text, nullable=True)
    account_details = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref='orders')

    def get_status_display(self):
        status_display = {
            'pending': 'Pendiente de pago',
            'processing': 'Procesando pago',
            'completed': 'Completado',
            'cancelled': 'Cancelado'
        }
        return status_display.get(self.status, self.status)

# Agrega estas rutas para manejar las ofertas
@app.route('/admin/offers')
@login_required
def admin_offers():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    offers = Offer.query.all()
    return render_template('admin_offers.html', offers=offers)

@app.route('/admin/offer/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_offer(id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    if id == 0:
        offer = None
    else:
        offer = Offer.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            if offer is None:
                offer = Offer()
                db.session.add(offer)
            
            offer.title = request.form.get('title')
            offer.description = request.form.get('description')
            offer.price = float(request.form.get('price'))
            offer.regular_price = float(request.form.get('regular_price'))
            offer.whatsapp_link = request.form.get('whatsapp_link')
            offer.is_active = 'is_active' in request.form
            
            db.session.commit()
            flash('Oferta guardada exitosamente', 'success')
            return redirect(url_for('admin_offers'))
            
        except Exception as e:
            flash(f'Error al guardar la oferta: {str(e)}', 'error')
            print(f"Error: {str(e)}")
            db.session.rollback()
    
    return render_template('edit_offer.html', offer=offer)

@app.route('/admin/offer/delete/<int:id>', methods=['POST'])
@login_required
def delete_offer(id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    try:
        offer = Offer.query.get_or_404(id)
        if offer.image_url:
            try:
                os.remove(os.path.join(app.root_path, offer.image_url))
            except Exception as e:
                print(f"Error removing image: {str(e)}")
        
        db.session.delete(offer)
        db.session.commit()
        flash('Oferta eliminada exitosamente', 'success')
    except Exception as e:
        flash(f'Error al eliminar la oferta: {str(e)}', 'error')
        db.session.rollback()
    
    return redirect(url_for('admin_offers'))

@app.route('/admin/offer/upload_image/<int:id>', methods=['POST'])
@login_required
def upload_offer_image(id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    offer = Offer.query.get_or_404(id)
    
    if 'image' not in request.files:
        flash('No se seleccionó ninguna imagen', 'error')
        return redirect(url_for('edit_offer', id=id))
        
    file = request.files['image']
    if file.filename == '':
        flash('No se seleccionó ninguna imagen', 'error')
        return redirect(url_for('edit_offer', id=id))
        
    if file and allowed_file(file.filename):
        if offer.image_url:
            old_image_path = os.path.join(app.root_path, offer.image_url)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)
        
        filename = secure_filename(file.filename)
        filename = f"offer_{int(time.time())}_{filename}"
        file.save(os.path.join(app.root_path, UPLOAD_FOLDER, filename))
        
        offer.image_url = f'{UPLOAD_FOLDER}/{filename}'
        db.session.commit()
        flash('Imagen actualizada exitosamente', 'success')
    else:
        flash('Formato de archivo no permitido', 'error')
        
    return redirect(url_for('edit_offer', id=id))
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_code(length=20):  # 20 + 5 prefix = 25 dígitos
    prefix = "FNNGG"
    consonants = ''.join(c for c in string.ascii_uppercase if c not in 'AEIOU')
    numbers = string.digits
    allowed_chars = consonants + numbers
    random_part = ''.join(random.choice(allowed_chars) for _ in range(length))
    return f"{prefix}{random_part}"
    consonants = 'BCDFGHJKLMNPQRSTVWXYZ'
    numbers = '0123456789'
    allowed_chars = consonants + numbers
    random_part = ''.join(random.choice(allowed_chars) for _ in range(length))
    return f"{prefix}{random_part}"


# Rutas
@app.route('/')
def index():
    products = Product.query.all()
    # Obtener la primera oferta activa
    offer = Offer.query.filter_by(is_active=True).first()
    return render_template('index.html', products=products, offer=offer)

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
            # Redirige directo al dashboard en lugar de verify_2fa
            return redirect(url_for('user_dashboard' if not user.is_admin else 'admin'))
        
        flash('Usuario o contraseña incorrectos', 'error')
    return render_template('user_login.html')


    

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin'))
    return render_template('user_dashboard.html', Order=Order)

@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin'))
    return render_template('user_dashboard.html')

@app.route('/user/orders')
@login_required
def user_orders():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('user_orders.html', orders=orders)

@app.route('/order/<int:order_id>/details')
@login_required
def order_details(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        return jsonify({'error': 'No autorizado'}), 403
    
    return jsonify({
        'payment_method': order.payment_method,
        'status': order.status,
        'total_amount': "%.2f" % order.total_amount,
        'created_at': order.created_at.strftime('%d/%m/%Y %H:%M')
    })

@app.route('/user/order/<int:order_id>')
@login_required
def user_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('user_dashboard'))
    return render_template('user_order_detail.html', order=order)

@app.route('/preview-code/<code>')
@login_required
def preview_code(code):
    redeem_code = RedeemCode.query.filter_by(code=code, is_used=False).first()
    if redeem_code:
        masked_code = '*' * 20 + code[-5:]  # Muestra solo los últimos 5 dígitos
        return jsonify({
            'valid': True,
            'amount': redeem_code.amount,
            'masked_code': masked_code
        })
    return jsonify({'valid': False})

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
    return render_template('admin.html', 
                         products=products,
                         Product=Product,
                         Order=Order,
                         User=User,
                         RedeemCode=RedeemCode)

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

@app.route('/admin/orders')
@login_required
def admin_orders():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template('admin_orders.html', orders=orders, Order=Order)

@app.route('/admin/order/<int:order_id>/add-account', methods=['POST'])
@login_required
def add_order_account(order_id):
    if not current_user.is_admin:
        return jsonify({'error': 'No autorizado'}), 403
    
    data = request.get_json()
    account_details = data.get('accountDetails')
    
    try:
        order = Order.query.get_or_404(order_id)
        order.account_details = account_details
        db.session.commit()
        return jsonify({'message': 'Cuenta agregada correctamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/order/<int:order_id>/update-status', methods=['POST'])
@login_required
def update_order_status(order_id):
    if not current_user.is_admin:
        return jsonify({'error': 'No autorizado'}), 403
    
    data = request.get_json()
    new_status = data.get('status')
    
    if new_status not in ['pending', 'processing', 'completed', 'cancelled']:
        return jsonify({'error': 'Estado no válido'}), 400
    
    try:
        order = Order.query.get_or_404(order_id)
        order.status = new_status
        db.session.commit()
        return jsonify({'message': 'Estado actualizado correctamente'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/order/<int:order_id>/details')
@login_required
def get_order_details(order_id):
    if not current_user.is_admin:
        return jsonify({'error': 'No autorizado'}), 403
    
    order = Order.query.get_or_404(order_id)
    return jsonify({
        'order': {
            'id': order.id,
            'total_amount': "%.2f" % order.total_amount,
            'payment_method': order.payment_method,
            'status': order.status,
            'payment_details': order.payment_details,
            'created_at': order.created_at.strftime('%d/%m/%Y %H:%M')
        },
        'user': {
            'username': order.user.username,
            'id': order.user.id
        }
    })

@app.route('/product/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            expiration_date = datetime.strptime(request.form.get('expiration_date'), '%Y-%m-%d')
            new_product = Product(
                name=request.form.get('name'),
                price=float(request.form.get('price')),
                features=request.form.get('features'),
                expiration_date=expiration_date
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
            expiration_date = datetime.strptime(request.form.get('expiration_date'), '%Y-%m-%d')
            product.name = request.form.get('name')
            product.price = float(request.form.get('price'))
            product.features = request.form.get('features')
            product.expiration_date = expiration_date
            
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

# Rutas del carrito
@app.route('/cart/add/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart:
        cart = Cart(user_id=current_user.id)
        db.session.add(cart)
    
    product = Product.query.get_or_404(product_id)
    cart_item = CartItem.query.filter_by(cart_id=cart.id, product_id=product_id).first()
    
    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = CartItem(cart_id=cart.id, product_id=product_id)
        db.session.add(cart_item)
    
    db.session.commit()
    flash('Producto agregado al carrito', 'success')
    return redirect(url_for('view_cart'))

@app.route('/cart')
@login_required
def view_cart():
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    payment_methods = [
        {
            'id': 'credit',
            'name': 'Créditos disponibles',
            'description': f'Saldo actual: ${current_user.credit}'
        },
        {
            'id': 'binance',
            'name': 'Binance USDT',
            'description': 'Pagar con USDT en Binance'
        },
        {
            'id': 'bank_transfer',
            'name': 'Transferencia/OXXO',
            'description': 'Pagar mediante transferencia bancaria o depósito en OXXO'
        }
    ]
    return render_template('cart.html', cart=cart, payment_methods=payment_methods)

@app.route('/cart/update/<int:item_id>', methods=['POST'])
@login_required
def update_cart_item(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    if cart_item.cart.user_id != current_user.id:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('view_cart'))
    
    quantity = int(request.form.get('quantity', 1))
    if quantity < 1:
        db.session.delete(cart_item)
    else:
        cart_item.quantity = quantity
    
    db.session.commit()
    return redirect(url_for('view_cart'))

@app.route('/cart/checkout', methods=['POST'])
@login_required
def checkout():
    cart = Cart.query.filter_by(user_id=current_user.id).first()
    if not cart or not cart.items:
        flash('El carrito está vacío', 'error')
        return redirect(url_for('view_cart'))
    
    payment_method = request.form.get('payment_method')
    if payment_method == 'credit':
        if current_user.credit < cart.total:
            flash('Saldo insuficiente', 'error')
            return redirect(url_for('view_cart'))
        
        current_user.credit -= cart.total
        order = Order(
            user_id=current_user.id,
            total_amount=cart.total,
            payment_method='credit',
            status='paid'
        )
        db.session.add(order)
        db.session.delete(cart)
        db.session.commit()
        flash('Compra realizada con éxito', 'success')
        return redirect(url_for('order_complete', order_id=order.id))
    
    elif payment_method in ['binance', 'bank_transfer']:
        order = Order(
            user_id=current_user.id,
            total_amount=cart.total,
            payment_method=payment_method,
            status='pending'
        )
        db.session.add(order)
        db.session.delete(cart)
        db.session.commit()
        return redirect(url_for('payment_instructions', order_id=order.id))
    
    flash('Método de pago no válido', 'error')
    return redirect(url_for('view_cart'))

@app.route('/order/<int:order_id>/complete')
@login_required
def order_complete(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    return render_template('order_complete.html', order=order)

@app.route('/order/<int:order_id>/payment-instructions')
@login_required
def payment_instructions(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    return render_template('payment_instructions.html', order=order)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/edit/<int:id>', methods=['POST'])
@login_required
def edit_user_credit(id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(id)
    try:
        new_credit = float(request.form.get('credit', 0))
        user.credit = new_credit
        db.session.commit()
        flash(f'Saldo actualizado exitosamente para {user.username}', 'success')
    except ValueError:
        flash('El valor del saldo debe ser un número', 'error')
    except Exception as e:
        flash('Error al actualizar el saldo', 'error')
        print(f"Error: {str(e)}")
    
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if not current_user.is_admin:
        flash('Acceso no autorizado', 'error')
        return redirect(url_for('index'))
    
    if id == current_user.id:
        flash('No puedes eliminar tu propia cuenta de administrador', 'error')
        return redirect(url_for('admin_users'))
    
    try:
        user = User.query.get_or_404(id)
        if user.is_admin:
            flash('No se pueden eliminar cuentas de administrador', 'error')
            return redirect(url_for('admin_users'))
            
        # Eliminar códigos relacionados
        RedeemCode.query.filter_by(used_by=user.id).update({'used_by': None})
        
        # Eliminar usuario
        db.session.delete(user)
        db.session.commit()
        flash(f'Usuario {user.username} eliminado exitosamente', 'success')
    except Exception as e:
        flash('Error al eliminar el usuario', 'error')
        print(f"Error: {str(e)}")
    
    return redirect(url_for('admin_users'))

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
                'price': 299.00,
                'features': 'Xbox Live Gold incluido\n+100 juegos para consola y PC\nEA Play incluido\nJuegos día 1 de lanzamiento',
                'expiration_date': datetime.now() + timedelta(days=90)  # 3 meses
            },
            {
                'name': 'Xbox Live Gold',
                'price': 149.00,
                'features': 'Multijugador en línea\n2-4 juegos gratis al mes\nDescuentos exclusivos',
                'expiration_date': datetime.now() + timedelta(days=30)  # 1 mes
            },
            {
                'name': 'Game Pass',
                'price': 229.00,
                'features': '+100 juegos de alta calidad\nNuevos juegos cada mes\nDescuentos exclusivos',
                'expiration_date': datetime.now() + timedelta(days=60)  # 2 meses
            }
        ]
        
        for product_data in products:
            product = Product(**product_data)
            db.session.add(product)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        # Crea todas las tablas
        db.create_all()

        # Crear usuario admin inicial si no existe
        if not User.query.filter_by(username='sakih').first():
            user = User(
                username='sakih',
                password_hash=generate_password_hash('sakih11F@@'),
                is_admin=True
            )
            db.session.add(user)
            db.session.commit()
        
        # Crear productos iniciales
        create_initial_products()
    
    app.run(debug=True)
