# StyleHub Pro - Cyber Fashion E-commerce

A futuristic e-commerce platform with cyber security theme, featuring advanced payment systems and admin management.

## Features

### 🚀 Core Features
- **User Authentication** with SMS OTP verification
- **Product Catalog** with 20 cyber fashion items
- **Shopping Cart** with real-time updates
- **5 Payment Gateways**: PayPal, Stripe, Razorpay, Crypto, Bank Transfer
- **Order Management** system
- **Admin Dashboard** with full control

### 🔐 Security Features
- SMS-based OTP verification
- Secure password hashing
- Session management
- Admin access controls

### 🎨 Design
- Cyber security theme with neon colors
- Matrix-style background effects
- Responsive design
- Futuristic typography

## Setup Instructions

1. **Install Dependencies**
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

2. **Add Product Images**
   - Create folder: `static/product_images/`
   - Add 20 product images named: `product1.jpg` to `product20.jpg`
   - Images should be at least 500x500px for best display

3. **Run the Application**
   \`\`\`bash
   python app.py
   \`\`\`

4. **Access the Application**
   - Main site: http://localhost:5000
   - Admin panel: http://localhost:5000/admin

## Demo Credentials

### Admin Access
- Username: `admin`
- Password: `admin123`

### Demo User
- Username: `demo`
- Password: `demo123`

## Database

The application uses SQLite database (`stylehub_cyber.db`) which is automatically created when you first run the application.

## Product Images Setup

Place your product images in `static/product_images/` with these names:
- product1.jpg - Neon City Cyber-Jacket
- product2.jpg - Ghost Protocol Trench Coat
- product3.jpg - Data Stream Bomber
- product4.jpg - Circuitry Hoodie
- product5.jpg - Quantum Weave Tee
- product6.jpg - Aether Vision Goggles
- product7.jpg - Neuro-Optics Shades
- product8.jpg - Neural Link Bracelet
- product9.jpg - Digital Ghost Gloves
- product10.jpg - Urban Recon Boots
- product11.jpg - Modular Cyber Pack
- product12.jpg - Chronos Smartwatch
- product13.jpg - Synthweave Dress
- product14.jpg - Stealth Ops Vest
- product15.jpg - Infrared Recon Jacket
- product16.jpg - Circuit Cap
- product17.jpg - Matrix Cargo Pants
- product18.jpg - Quantum Belt
- product19.jpg - Data Heist Sling Bag
- product20.jpg - Cyber Samurai Vest

## Features Overview

### User Features
- Registration with SMS verification
- Secure login/logout
- Product browsing and search
- Shopping cart management
- Multiple payment options
- Order tracking
- User dashboard

### Admin Features
- Complete admin dashboard
- User management
- Product management
- Order management
- Inventory tracking
- Sales analytics
- Low stock alerts

### Payment Integration
- Demo payment gateways configured
- Real payment processing ready
- Multiple currency support
- Secure transaction handling

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, JavaScript
- **Styling**: Bootstrap 5, Custom CSS
- **Icons**: Font Awesome
- **Fonts**: Google Fonts (Orbitron, Rajdhani)

## Security Features

- Password hashing
- Session management
- CSRF protection
- SQL injection prevention
- XSS protection
- Secure file uploads

## Customization

### Adding New Products
1. Access admin panel
2. Go to Product Management
3. Add product details and images
4. Set pricing and inventory

### Modifying Theme
- Edit CSS variables in `templates/base.html`
- Customize colors, fonts, and animations
- Update cyber theme elements

### Payment Configuration
- Update payment gateway credentials in `app.py`
- Configure webhook URLs for production
- Set up proper SSL certificates

## Production Deployment

1. **Environment Variables**
   - Set production database URL
   - Configure payment gateway keys
   - Set secure secret keys

2. **Security**
   - Enable HTTPS
   - Configure firewall
   - Set up monitoring

3. **Performance**
   - Enable caching
   - Optimize database queries
   - Use CDN for static files

## File Structure

\`\`\`
stylehub-pro/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # Project documentation
├── stylehub_cyber.db     # SQLite database (auto-created)
├── static/
│   └── product_images/   # Product image directory
└── templates/
    ├── base.html         # Base template
    ├── index.html        # Homepage
    ├── register.html     # User registration
    ├── login.html        # User login
    ├── otp_verification.html # OTP verification
    ├── dashboard.html    # User dashboard
    ├── products.html     # Product listing
    ├── product_detail.html # Product details
    ├── cart.html         # Shopping cart
    ├── checkout.html     # Checkout page
    ├── order_confirmation.html # Order confirmation
    └── admin/
        ├── dashboard.html # Admin dashboard
        ├── products.html  # Product management
        ├── orders.html    # Order management
        └── users.html     # User management
\`\`\`

## Support

For technical support or questions:
- Check the documentation
- Review error logs
- Contact development team

## License

This project is licensed under the MIT License.

---

**StyleHub Pro - Where Cyber Fashion Meets Security**
