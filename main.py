from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import secrets
import os
import requests
from functools import wraps
import re
import logging
import time
import json
import hashlib
import hmac
import base64

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cyber-security-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stylehub_cyber.db'  # SQLite Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/product_images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Payment Gateway Configuration (Demo/Test keys)
PAYPAL_CLIENT_ID = "demo_paypal_client_id"
PAYPAL_CLIENT_SECRET = "demo_paypal_secret"
STRIPE_PUBLISHABLE_KEY = "pk_test_demo_stripe_key"
STRIPE_SECRET_KEY = "sk_test_demo_stripe_key"
RAZORPAY_KEY_ID = "rzp_test_demo_key"
RAZORPAY_KEY_SECRET = "demo_razorpay_secret"

# Initialize database
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    phone = db.Column(db.String(20), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)
    
    # Address Information
    full_name = db.Column(db.String(100))
    address_line1 = db.Column(db.String(200))
    address_line2 = db.Column(db.String(200))
    city = db.Column(db.String(50))
    state = db.Column(db.String(50))
    pincode = db.Column(db.String(10))

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), nullable=False, index=True)
    otp_code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    purpose = db.Column(db.String(20), default='registration')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    original_price = db.Column(db.Float)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    image_url = db.Column(db.String(200))
    image_gallery = db.Column(db.Text)  # JSON array of image URLs
    stock_quantity = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)
    is_new = db.Column(db.Boolean, default=False)
    is_bestseller = db.Column(db.Boolean, default=False)
    rating = db.Column(db.Float, default=0.0)
    review_count = db.Column(db.Integer, default=0)
    sizes = db.Column(db.Text)  # JSON array of available sizes
    colors = db.Column(db.Text)  # JSON array of available colors
    specifications = db.Column(db.Text)  # JSON object of specifications
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    category = db.relationship('Category', backref=db.backref('products', lazy=True))
    
    @property
    def sizes_list(self):
        return json.loads(self.sizes) if self.sizes else []
    
    @property
    def colors_list(self):
        return json.loads(self.colors) if self.colors else []
    
    @property
    def specifications_dict(self):
        return json.loads(self.specifications) if self.specifications else {}

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    selected_size = db.Column(db.String(10))
    selected_color = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    user = db.relationship('User', backref=db.backref('cart_items', lazy=True))
    product = db.relationship('Product', backref=db.backref('cart_items', lazy=True))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_number = db.Column(db.String(20), unique=True, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    payment_status = db.Column(db.String(20), default='pending')
    payment_method = db.Column(db.String(50))
    payment_id = db.Column(db.String(100))
    shipping_address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    user = db.relationship('User', backref=db.backref('orders', lazy=True))

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    selected_size = db.Column(db.String(10))
    selected_color = db.Column(db.String(50))
    
    order = db.relationship('Order', backref=db.backref('items', lazy=True))
    product = db.relationship('Product', backref=db.backref('order_items', lazy=True))

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    payment_id = db.Column(db.String(100))
    transaction_id = db.Column(db.String(100))
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(10), default='USD')
    status = db.Column(db.String(20), default='pending')
    gateway_response = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    order = db.relationship('Order', backref=db.backref('payments', lazy=True))

# Helper Functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def generate_otp():
    return str(secrets.randbelow(900000) + 100000)

def generate_order_number():
    return f"SH{int(datetime.now().timestamp())}"

def validate_indian_phone(phone):
    pattern = r'^\+91[6-9]\d{9}$'
    return re.match(pattern, phone) is not None

def send_otp_sms(phone, otp_code):
    """Simulate SMS sending - In production, integrate with SMS gateway"""
    print(f"\n🔐 SMS OTP SENT TO {phone}")
    print(f"📱 OTP CODE: {otp_code}")
    print(f"⏰ Valid for 5 minutes")
    print("="*50)
    return True, "sms_sent"

def get_cart_count(user_id):
    if not user_id:
        return 0
    return db.session.query(db.func.sum(Cart.quantity)).filter_by(user_id=user_id).scalar() or 0

def get_cart_total(user_id):
    if not user_id:
        return 0
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    return total

# Helper function to get product image URL
def get_product_image_url(product_id):
    """Get the correct image URL for a product"""
    local_path = f"static/product_images/product{product_id}.jpg"
    if os.path.exists(local_path):
        return f"/static/product_images/product{product_id}.jpg"
    else:
        # Fallback to placeholder
        return f"https://picsum.photos/500/500?random={product_id}"

# Routes
@app.route('/')
def index():
    featured_products = Product.query.filter_by(is_featured=True, is_active=True).limit(12).all()
    categories = Category.query.filter_by(is_active=True).all()
    cart_count = get_cart_count(session.get('user_id'))
    return render_template('index.html', featured_products=featured_products, 
                         categories=categories, cart_count=cart_count)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, phone, password, confirm_password]):
            flash('All fields are required!', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('register.html')

        if User.query.filter_by(phone=phone).first():
            flash('Phone number already registered!', 'error')
            return render_template('register.html')

        if not validate_indian_phone(phone):
            flash('Please enter a valid Indian phone number starting with +91!', 'error')
            return render_template('register.html')
        
        try:
            user = User(
                username=username,
                phone=phone,
                password_hash=generate_password_hash(password),
                is_verified=False
            )
            db.session.add(user)
            db.session.commit()

            otp_code = generate_otp()
            expires_at = datetime.now() + timedelta(minutes=5)

            sms_sent, message_id = send_otp_sms(phone, otp_code)

            otp = OTP(
                phone=phone,
                otp_code=otp_code,
                expires_at=expires_at,
                purpose='registration'
            )
            db.session.add(otp)
            db.session.commit()
            
            session['unverified_user_id'] = user.id
            session['otp_phone'] = phone
            session['otp_purpose'] = 'registration'

            flash('Registration successful! Please verify your phone number.', 'success')
            return redirect(url_for('otp_verification'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {str(e)}', 'error')
            return render_template('register.html')
    return render_template('register.html')

@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    if 'unverified_user_id' not in session or 'otp_phone' not in session:
        flash('Invalid verification attempt. Please register again.', 'error')
        return redirect(url_for('register'))

    user = User.query.get(session['unverified_user_id'])
    phone = session['otp_phone']

    if not user:
        flash('User not found. Please register again.', 'error')
        return redirect(url_for('register'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')

        if not otp_code or len(otp_code) != 6:
            flash('Please enter a 6-digit OTP code.', 'error')
            return render_template('otp_verification.html', phone=phone)

        latest_otp = OTP.query.filter_by(phone=phone, otp_code=otp_code, is_used=False)\
                               .filter(OTP.expires_at > datetime.now())\
                               .order_by(OTP.created_at.desc()).first()

        if latest_otp:
            user.is_verified = True
            latest_otp.is_used = True
            db.session.commit()

            session.pop('unverified_user_id', None)
            session.pop('otp_phone', None)
            session.pop('otp_purpose', None)

            flash('Phone number verified successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'error')
            return render_template('otp_verification.html', phone=phone)

    return render_template('otp_verification.html', phone=phone)

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    if 'otp_phone' not in session:
        return jsonify(success=False, message='Invalid request to resend OTP.')

    phone = session['otp_phone']
    
    try:
        otp_code = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=5)
        
        sms_sent, message_id = send_otp_sms(phone, otp_code)

        new_otp = OTP(
            phone=phone,
            otp_code=otp_code,
            expires_at=expires_at,
            purpose=session.get('otp_purpose', 'registration')
        )
        db.session.add(new_otp)
        db.session.commit()

        return jsonify(success=True, message='OTP resent successfully!')
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f'Failed to resend OTP: {str(e)}')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_phone = request.form.get('username')
        password = request.form.get('password')

        if not username_or_phone or not password:
            flash('Please enter both username/phone and password.', 'error')
            return render_template('login.html')

        user = User.query.filter((User.username == username_or_phone) | (User.phone == username_or_phone)).first()

        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                session['unverified_user_id'] = user.id
                session['otp_phone'] = user.phone
                session['otp_purpose'] = 'login_verification'
                flash('Your account is not verified. Please verify your phone number.', 'info')
                return redirect(url_for('otp_verification'))
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            user.last_login = datetime.now()
            db.session.commit()
            flash('Login successful!', 'success')
            
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username/phone or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    user = User.query.get(user_id)
    recent_orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).limit(5).all()
    cart_count = get_cart_count(user_id)
    return render_template('dashboard.html', user=user, recent_orders=recent_orders, cart_count=cart_count)

@app.route('/products')
def products():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    category_id = request.args.get('category', type=int)
    sort_by = request.args.get('sort', 'name')
    
    query = Product.query.filter_by(is_active=True)
    
    if search:
        query = query.filter(Product.name.contains(search) | Product.description.contains(search))
    
    if category_id:
        query = query.filter_by(category_id=category_id)
    
    # Sorting
    if sort_by == 'price_low':
        query = query.order_by(Product.price.asc())
    elif sort_by == 'price_high':
        query = query.order_by(Product.price.desc())
    elif sort_by == 'rating':
        query = query.order_by(Product.rating.desc())
    elif sort_by == 'newest':
        query = query.order_by(Product.created_at.desc())
    else:
        query = query.order_by(Product.name.asc())
    
    products = query.paginate(page=page, per_page=12, error_out=False)
    categories = Category.query.filter_by(is_active=True).all()
    cart_count = get_cart_count(session.get('user_id'))
    
    return render_template('products.html', products=products, categories=categories, 
                         cart_count=cart_count, search=search, current_category=category_id, sort_by=sort_by)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    related_products = Product.query.filter(
        Product.category_id == product.category_id,
        Product.id != product.id,
        Product.is_active == True
    ).limit(4).all()
    cart_count = get_cart_count(session.get('user_id'))
    return render_template('product_detail.html', product=product, 
                         related_products=related_products, cart_count=cart_count)

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity', 1))
    selected_size = request.form.get('selected_size')
    selected_color = request.form.get('selected_color')
    user_id = session['user_id']

    product = Product.query.get(product_id)
    if not product:
        return jsonify(success=False, message='Product not found.')

    if quantity <= 0:
        return jsonify(success=False, message='Quantity must be at least 1.')

    if quantity > product.stock_quantity:
        return jsonify(success=False, message=f'Only {product.stock_quantity} items available.')

    # Check if item already in cart
    cart_item = Cart.query.filter_by(
        user_id=user_id, 
        product_id=product_id, 
        selected_size=selected_size, 
        selected_color=selected_color
    ).first()
    
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = Cart(
            user_id=user_id, 
            product_id=product_id, 
            quantity=quantity, 
            selected_size=selected_size, 
            selected_color=selected_color
        )
        db.session.add(cart_item)
    
    db.session.commit()
    
    cart_count = get_cart_count(user_id)
    return jsonify(success=True, message=f'{quantity} x {product.name} added to cart!', cart_count=cart_count)

@app.route('/cart')
@login_required
def cart():
    user_id = session['user_id']
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    cart_total = get_cart_total(user_id)
    cart_count = get_cart_count(user_id)
    return render_template('cart.html', cart_items=cart_items, cart_total=cart_total, cart_count=cart_count)

@app.route('/update_cart_item/<int:item_id>', methods=['POST'])
@login_required
def update_cart_item(item_id):
    quantity = int(request.form.get('quantity', 0))
    user_id = session['user_id']

    cart_item = Cart.query.filter_by(id=item_id, user_id=user_id).first()

    if not cart_item:
        return jsonify(success=False, message='Cart item not found.')

    if quantity <= 0:
        db.session.delete(cart_item)
        message = 'Item removed from cart.'
    else:
        if quantity > cart_item.product.stock_quantity:
            return jsonify(success=False, message=f'Only {cart_item.product.stock_quantity} items available.')
        cart_item.quantity = quantity
        message = 'Cart updated successfully.'
    
    db.session.commit()
    
    cart_total = get_cart_total(user_id)
    cart_count = get_cart_count(user_id)
    return jsonify(success=True, message=message, cart_total=cart_total, cart_count=cart_count)

@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    user_id = session['user_id']
    cart_item = Cart.query.filter_by(id=item_id, user_id=user_id).first()

    if not cart_item:
        return jsonify(success=False, message='Cart item not found.')

    db.session.delete(cart_item)
    db.session.commit()

    cart_total = get_cart_total(user_id)
    cart_count = get_cart_count(user_id)
    return jsonify(success=True, message='Item removed from cart.', cart_total=cart_total, cart_count=cart_count)

@app.route('/checkout')
@login_required
def checkout():
    user_id = session['user_id']
    user = User.query.get(user_id)
    cart_items = Cart.query.filter_by(user_id=user_id).all()

    if not cart_items:
        flash('Your cart is empty!', 'error')
        return redirect(url_for('cart'))

    cart_total = get_cart_total(user_id)
    cart_count = get_cart_count(user_id)

    return render_template('checkout.html', 
                           cart_items=cart_items, 
                           cart_total=cart_total, 
                           cart_count=cart_count,
                           user=user,
                           stripe_publishable_key=STRIPE_PUBLISHABLE_KEY,
                           razorpay_key_id=RAZORPAY_KEY_ID)

@app.route('/process_payment', methods=['POST'])
@login_required
def process_payment():
    payment_method = request.form.get('payment_method')
    user_id = session['user_id']
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    cart_total = get_cart_total(user_id)
    user = User.query.get(user_id)

    if not cart_items:
        return jsonify(success=False, message='Your cart is empty!')
    if cart_total <= 0:
        return jsonify(success=False, message='Cart total must be greater than zero.')

    try:
        # Create Order
        order = Order(
            user_id=user_id,
            order_number=generate_order_number(),
            total_amount=cart_total,
            status='confirmed',
            payment_status='completed',  # Simulating successful payment
            payment_method=payment_method,
            payment_id=f"demo_{payment_method}_{int(datetime.now().timestamp())}",
            shipping_address=json.dumps({
                "full_name": user.full_name or user.username,
                "address_line1": user.address_line1 or "Demo Address",
                "city": user.city or "Demo City",
                "state": user.state or "Demo State",
                "pincode": user.pincode or "123456"
            })
        )
        db.session.add(order)
        db.session.flush()

        # Add Order Items
        for item in cart_items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item.product_id,
                quantity=item.quantity,
                price=item.product.price,
                selected_size=item.selected_size,
                selected_color=item.selected_color
            )
            db.session.add(order_item)
            
            # Update stock
            item.product.stock_quantity -= item.quantity
            
            # Clear cart
            db.session.delete(item)

        # Record Payment
        payment_record = Payment(
            order_id=order.id,
            payment_method=payment_method,
            payment_id=order.payment_id,
            transaction_id=f"txn_{int(datetime.now().timestamp())}",
            amount=cart_total,
            currency='USD',
            status='completed',
            gateway_response=json.dumps({"status": "demo_success", "method": payment_method})
        )
        db.session.add(payment_record)

        db.session.commit()

        return jsonify(success=True, message="Payment successful and order placed!", order_id=order.id)

    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f'An error occurred during payment: {str(e)}')

@app.route('/order_confirmation/<int:order_id>')
@login_required
def order_confirmation(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != session['user_id']:
        flash('You do not have permission to view this order.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('order_confirmation.html', order=order)

# Admin Routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_products = Product.query.count()
    total_orders = Order.query.count()
    total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter_by(payment_status='completed').scalar() or 0
    
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    low_stock_products = Product.query.filter(Product.stock_quantity < 10).all()
    
    return render_template('admin/dashboard.html', 
                         total_users=total_users,
                         total_products=total_products,
                         total_orders=total_orders,
                         total_revenue=total_revenue,
                         recent_orders=recent_orders,
                         low_stock_products=low_stock_products)

@app.route('/admin/products')
@admin_required
def admin_products():
    page = request.args.get('page', 1, type=int)
    products = Product.query.order_by(Product.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False)
    return render_template('admin/products.html', products=products)

@app.route('/admin/orders')
@admin_required
def admin_orders():
    page = request.args.get('page', 1, type=int)
    orders = Order.query.order_by(Order.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False)
    return render_template('admin/orders.html', orders=orders)

@app.route('/admin/users')
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False)
    return render_template('admin/users.html', users=users)

@app.route('/admin/update_order_status/<int:order_id>', methods=['POST'])
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    
    if new_status in ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled']:
        order.status = new_status
        order.updated_at = datetime.now()
        db.session.commit()
        flash(f'Order {order.order_number} status updated to {new_status}', 'success')
    else:
        flash('Invalid status', 'error')
    
    return redirect(url_for('admin_orders'))

# Static file serving for product images
@app.route('/static/product_images/<filename>')
def product_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Template filter for JSON parsing
@app.template_filter('from_json')
def from_json_filter(value):
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return {}

# Database initialization
def init_db():
    with app.app_context():
        db.create_all()
        
        # Clear existing data
        db.session.query(OrderItem).delete()
        db.session.query(Payment).delete()
        db.session.query(Order).delete()
        db.session.query(Cart).delete()
        db.session.query(Product).delete()
        db.session.query(Category).delete()
        db.session.query(OTP).delete()
        db.session.query(User).delete()
        db.session.commit()
        
        # Create admin user
        admin_user = User(
            username='admin',
            phone='+919999999999',
            password_hash=generate_password_hash('admin123'),
            is_admin=True,
            is_verified=True,
            full_name='Admin User',
            email='admin@stylehub.com'
        )
        db.session.add(admin_user)
        
        # Create demo user
        demo_user = User(
            username='demo',
            phone='+919876543210',
            password_hash=generate_password_hash('demo123'),
            is_admin=False,
            is_verified=True,
            full_name='Demo User',
            email='demo@stylehub.com'
        )
        db.session.add(demo_user)
        
        # Create category
        cyber_category = Category(
            name='Cyber Fashion',
            description='Futuristic and edgy clothing, accessories, and tech-wear.',
            image_url='static/images/cyber-category.jpg'
        )
        db.session.add(cyber_category)
        db.session.commit()
        
        # Create 20 products with fallback image URLs
        products_data = [
            {
                "name": "Neon City Cyber-Jacket",
                "description": "Illuminate the urban sprawl with this reflective, waterproof cyber-jacket featuring integrated LED strips and a tactical design.",
                "price": 299.99, "original_price": 350.00,
                "image_url": "/static/product_images/product1.jpg",
                "stock_quantity": 25,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.8, "review_count": 150,
                "sizes": json.dumps(["S", "M", "L", "XL"]),
                "colors": json.dumps(["Black/Blue", "Black/Red", "Silver/Green"]),
                "specifications": json.dumps({"Material": "Dyneema Composite", "Features": "Active Cooling, Holographic Display Cuffs"})
            },
            {
                "name": "Ghost Protocol Trench Coat",
                "description": "Stealth and style converge. A durable, tech-infused trench coat with hidden pockets and climate control.",
                "price": 450.00, "original_price": 520.00,
                "image_url": "/static/product_images/product2.jpg",
                "stock_quantity": 15,
                "is_new": False, "is_bestseller": True, "is_featured": True,
                "rating": 4.9, "review_count": 230,
                "sizes": json.dumps(["M", "L", "XL"]),
                "colors": json.dumps(["Dark Gray", "Olive Green"]),
                "specifications": json.dumps({"Material": "Nano-fiber", "Features": "Invisibility Cloak (limited), Self-repairing"})
            },
            {
                "name": "Data Stream Bomber",
                "description": "Lightweight and agile, this bomber jacket is perfect for quick urban transits. Equipped with a secure data port.",
                "price": 180.00, "original_price": 200.00,
                "image_url": "/static/product_images/product3.jpg",
                "stock_quantity": 30,
                "is_new": True, "is_bestseller": False, "is_featured": False,
                "rating": 4.5, "review_count": 90,
                "sizes": json.dumps(["S", "M", "L"]),
                "colors": json.dumps(["Black", "White", "Neon Yellow"]),
                "specifications": json.dumps({"Material": "Synthetic", "Features": "USB-C Charging, Water-resistant"})
            },
            {
                "name": "Circuitry Hoodie",
                "description": "A comfortable hoodie with an intricate circuitry pattern. Ideal for casual cyber gatherings.",
                "price": 85.00, "original_price": None,
                "image_url": "/static/product_images/product4.jpg",
                "stock_quantity": 50,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.7, "review_count": 180,
                "sizes": json.dumps(["XS", "S", "M", "L", "XL"]),
                "colors": json.dumps(["Gray/Green", "Black/Blue"]),
                "specifications": json.dumps({"Material": "Organic Cotton Blend", "Features": "Glow-in-the-dark print"})
            },
            {
                "name": "Quantum Weave Tee",
                "description": "A performance tee designed for optimal data flow and comfort. Breathable and quick-drying.",
                "price": 55.00, "original_price": 65.00,
                "image_url": "/static/product_images/product5.jpg",
                "stock_quantity": 40,
                "is_new": False, "is_bestseller": False, "is_featured": True,
                "rating": 4.6, "review_count": 110,
                "sizes": json.dumps(["S", "M", "L"]),
                "colors": json.dumps(["Black", "White", "Electric Blue"]),
                "specifications": json.dumps({"Material": "Syntactic Fiber", "Features": "Moisture-wicking, Anti-bacterial"})
            },
            {
                "name": "Aether Vision Goggles",
                "description": "See the world through a new lens. Integrated AR display and threat detection.",
                "price": 120.00, "original_price": 150.00,
                "image_url": "/static/product_images/product6.jpg",
                "stock_quantity": 20,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.9, "review_count": 280,
                "sizes": json.dumps(["One Size"]),
                "colors": json.dumps(["Black", "Transparent"]),
                "specifications": json.dumps({"Lens Type": "Smart Glass", "Battery Life": "8 hours"})
            },
            {
                "name": "Neuro-Optics Shades",
                "description": "Sleek, lightweight shades that offer UV protection and a minimalist cyber aesthetic.",
                "price": 75.00, "original_price": None,
                "image_url": "/static/product_images/product7.jpg",
                "stock_quantity": 35,
                "is_new": False, "is_bestseller": False, "is_featured": True,
                "rating": 4.5, "review_count": 120,
                "sizes": json.dumps(["One Size"]),
                "colors": json.dumps(["Silver", "Matte Black"]),
                "specifications": json.dumps({"Lens Type": "Polarized", "Frame Material": "Titanium Alloy"})
            },
            {
                "name": "Neural Link Bracelet",
                "description": "A stylish bracelet with integrated health monitoring and limited-range communication capabilities.",
                "price": 95.00, "original_price": 110.00,
                "image_url": "/static/product_images/product8.jpg",
                "stock_quantity": 25,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.7, "review_count": 190,
                "sizes": json.dumps(["S/M", "M/L"]),
                "colors": json.dumps(["Black", "Rose Gold", "Chrome"]),
                "specifications": json.dumps({"Connectivity": "Bluetooth 6.0", "Battery Life": "48 hours"})
            },
            {
                "name": "Digital Ghost Gloves",
                "description": "Tactical gloves with touch-sensitive fingertips and reinforced knuckles for urban exploration.",
                "price": 60.00, "original_price": None,
                "image_url": "/static/product_images/product9.jpg",
                "stock_quantity": 45,
                "is_new": False, "is_bestseller": False, "is_featured": True,
                "rating": 4.4, "review_count": 70,
                "sizes": json.dumps(["S", "M", "L"]),
                "colors": json.dumps(["Black", "Forest Green"]),
                "specifications": json.dumps({"Material": "Reinforced Fabric", "Features": "Touchscreen Compatible"})
            },
            {
                "name": "Urban Recon Boots",
                "description": "Durable and agile boots designed for navigating complex cityscapes. Anti-slip sole and water-resistant.",
                "price": 160.00, "original_price": 190.00,
                "image_url": "/static/product_images/product10.jpg",
                "stock_quantity": 20,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.8, "review_count": 210,
                "sizes": json.dumps(["7", "8", "9", "10", "11", "12"]),
                "colors": json.dumps(["Black", "Desert Camo"]),
                "specifications": json.dumps({"Sole": "Vibram", "Material": "Gore-Tex"})
            },
            {
                "name": "Modular Cyber Pack",
                "description": "A versatile backpack with detachable compartments for all your tech essentials. RFID protected.",
                "price": 130.00, "original_price": None,
                "image_url": "/static/product_images/product11.jpg",
                "stock_quantity": 30,
                "is_new": True, "is_bestseller": False, "is_featured": False,
                "rating": 4.6, "review_count": 85,
                "sizes": json.dumps(["One Size"]),
                "colors": json.dumps(["Black", "Coyote Brown"]),
                "specifications": json.dumps({"Capacity": "25L", "Security": "Anti-theft zippers"})
            },
            {
                "name": "Chronos Smartwatch",
                "description": "Beyond timekeeping – integrated comms, health monitor, and discreet interface.",
                "price": 250.00, "original_price": 300.00,
                "image_url": "/static/product_images/product12.jpg",
                "stock_quantity": 15,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.9, "review_count": 300,
                "sizes": json.dumps(["One Size"]),
                "colors": json.dumps(["Black", "Silver"]),
                "specifications": json.dumps({"Display": "AMOLED", "Battery": "7 days", "OS": "QuantumOS"})
            },
            {
                "name": "Synthweave Dress",
                "description": "A sleek, form-fitting dress made from adaptive synthweave fabric that adjusts to your environment.",
                "price": 190.00, "original_price": 220.00,
                "image_url": "/static/product_images/product13.jpg",
                "stock_quantity": 25,
                "is_new": True, "is_bestseller": False, "is_featured": False,
                "rating": 4.7, "review_count": 130,
                "sizes": json.dumps(["XS", "S", "M", "L"]),
                "colors": json.dumps(["Deep Purple", "Electric Blue", "Matte Black"]),
                "specifications": json.dumps({"Material": "Adaptive Polymer", "Features": "Temperature regulating, Biometric sensors"})
            },
            {
                "name": "Stealth Ops Vest",
                "description": "Light tactical vest with multiple utility pouches and a minimalist design. Perfect for layering.",
                "price": 110.00, "original_price": None,
                "image_url": "/static/product_images/product14.jpg",
                "stock_quantity": 35,
                "is_new": False, "is_bestseller": True, "is_featured": False,
                "rating": 4.6, "review_count": 95,
                "sizes": json.dumps(["S", "M", "L", "XL"]),
                "colors": json.dumps(["Black", "Army Green"]),
                "specifications": json.dumps({"Material": "Ripstop Nylon", "Pockets": "6 internal, 4 external"})
            },
            {
                "name": "Infrared Recon Jacket",
                "description": "Equipped with advanced thermal camouflage and a lightweight design for discreet operations.",
                "price": 320.00, "original_price": 380.00,
                "image_url": "/static/product_images/product15.jpg",
                "stock_quantity": 12,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.8, "review_count": 160,
                "sizes": json.dumps(["M", "L", "XL"]),
                "colors": json.dumps(["Stealth Black", "Urban Camo"]),
                "specifications": json.dumps({"Technology": "Thermal Dampening", "Weatherproofing": "IP67 Rated"})
            },
            {
                "name": "Circuit Cap",
                "description": "A stylish cap with illuminated circuit lines, perfect for night city strolls.",
                "price": 45.00, "original_price": None,
                "image_url": "/static/product_images/product16.jpg",
                "stock_quantity": 60,
                "is_new": True, "is_bestseller": False, "is_featured": False,
                "rating": 4.3, "review_count": 60,
                "sizes": json.dumps(["One Size"]),
                "colors": json.dumps(["Black/Red", "Navy/Blue"]),
                "specifications": json.dumps({"Features": "LED accents", "Material": "Cotton-Poly Blend"})
            },
            {
                "name": "Matrix Cargo Pants",
                "description": "Functional and durable cargo pants with multiple reinforced pockets and a streamlined cyber aesthetic.",
                "price": 140.00, "original_price": 160.00,
                "image_url": "/static/product_images/product17.jpg",
                "stock_quantity": 28,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.7, "review_count": 140,
                "sizes": json.dumps(["28", "30", "32", "34", "36"]),
                "colors": json.dumps(["Black", "Khaki"]),
                "specifications": json.dumps({"Material": "Tech Cotton", "Pockets": "8"})
            },
            {
                "name": "Quantum Belt",
                "description": "A sleek, minimalist belt with a magnetic quick-release buckle and subtle glow-in-the-dark stitching.",
                "price": 65.00, "original_price": None,
                "image_url": "/static/product_images/product18.jpg",
                "stock_quantity": 40,
                "is_new": False, "is_bestseller": False, "is_featured": False,
                "rating": 4.4, "review_count": 55,
                "sizes": json.dumps(["One Size"]),
                "colors": json.dumps(["Black", "Metallic Gray"]),
                "specifications": json.dumps({"Buckle": "Magnetic", "Material": "Industrial Webbing"})
            },
            {
                "name": "Data Heist Sling Bag",
                "description": "Compact and secure sling bag, perfect for carrying essential cyber tools and personal devices.",
                "price": 90.00, "original_price": 105.00,
                "image_url": "/static/product_images/product19.jpg",
                "stock_quantity": 32,
                "is_new": True, "is_bestseller": True, "is_featured": True,
                "rating": 4.8, "review_count": 115,
                "sizes": json.dumps(["One Size"]),
                "colors": json.dumps(["Black", "OD Green"]),
                "specifications": json.dumps({"Pockets": "5", "Security": "Hidden zipper"})
            },
            {
                "name": "Cyber Samurai Vest",
                "description": "Inspired by ancient warriors and future tech, this vest offers both protection and style.",
                "price": 280.00, "original_price": 310.00,
                "image_url": "/static/product_images/product20.jpg",
                "stock_quantity": 18,
                "is_new": False, "is_bestseller": False, "is_featured": True,
                "rating": 4.6, "review_count": 80,
                "sizes": json.dumps(["S", "M", "L"]),
                "colors": json.dumps(["Red/Black", "White/Blue"]),
                "specifications": json.dumps({"Armor Plates": "Lightweight Polymer", "Ventilation": "Active"})
            }
        ]
        
        for p_data in products_data:
            product = Product(
                name=p_data['name'],
                description=p_data['description'],
                price=p_data['price'],
                original_price=p_data.get('original_price'),
                category=cyber_category,
                image_url=p_data['image_url'],
                stock_quantity=p_data['stock_quantity'],
                is_new=p_data['is_new'],
                is_bestseller=p_data['is_bestseller'],
                is_featured=p_data['is_featured'],
                rating=p_data['rating'],
                review_count=p_data['review_count'],
                sizes=p_data['sizes'],
                colors=p_data['colors'],
                specifications=p_data['specifications']
            )
            db.session.add(product)
        
        db.session.commit()
        
        print("\n🚀 STYLEHUB PRO - CYBER EDITION INITIALIZED")
        print("="*60)
        print("✅ Database: SQLite (stylehub_cyber.db)")
        print("✅ Products: 20 cyber fashion items")
        print("✅ Payment Gateways: 5 methods integrated")
        print("✅ Admin Dashboard: Full featured")
        print("✅ SMS Verification: Console-based")
        print("\n🔐 DEMO CREDENTIALS:")
        print("Admin: username='admin', password='admin123'")
        print("User:  username='demo', password='demo123'")
        print("\n📁 IMAGE SETUP:")
        print("Add product images to: static/product_images/")
        print("Files needed: product1.jpg to product20.jpg")
        print("="*60)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
