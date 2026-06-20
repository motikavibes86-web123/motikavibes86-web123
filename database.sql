-- SELVIX TECHNOLOGY DATABASE STRUCTURE
-- Created: 2026-06-20

-- ============================================================
-- 1. ADMIN TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS admin (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    profile_image VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default admin
INSERT INTO admin (email, password, name) VALUES 
('admin@selvix.com', '$2y$10$YourHashedPasswordHere', 'Selvix Admin');

-- ============================================================
-- 2. USERS TABLE (Wateja)
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    password VARCHAR(255) NOT NULL,
    profile_image VARCHAR(255),
    total_spent DECIMAL(15, 2) DEFAULT 0,
    status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    ip_address VARCHAR(45)
);

-- Sample Users
INSERT INTO users (full_name, email, phone_number, password, total_spent, status) VALUES
('Juma Hassan', 'juma@gmail.com', '0712345678', '$2y$10$hash1', 650000, 'active'),
('Asha Mohamed', 'asha@yahoo.com', '0756123456', '$2y$10$hash2', 350000, 'active'),
('Baraka John', 'baraka@icloud.com', '0623123456', '$2y$10$hash3', 1200000, 'active'),
('Neema Lucas', 'neema@gmail.com', '0765345678', '$2y$10$hash4', 0, 'active'),
('Hamza Ali', 'hamza@gmail.com', '0789456123', '$2y$10$hash5', 500000, 'active');

-- ============================================================
-- 3. PRODUCTS TABLE (Websites & Apps)
-- ============================================================
CREATE TABLE IF NOT EXISTS products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    category ENUM('website', 'app', 'bundle') NOT NULL,
    sub_category VARCHAR(100),
    price DECIMAL(15, 2) NOT NULL,
    description TEXT,
    features LONGTEXT, -- JSON format
    preview_image VARCHAR(255),
    demo_url VARCHAR(255),
    status ENUM('active', 'inactive') DEFAULT 'active',
    total_sales INT DEFAULT 0,
    total_revenue DECIMAL(15, 2) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Sample Products
INSERT INTO products (name, category, sub_category, price, description, features, status, total_sales, total_revenue) VALUES
('Selvix E-Commerce Lite', 'website', 'Shop', 650000, 'Lightweight e-commerce website', '["Product catalog", "Shopping cart", "Payment integration", "Basic analytics"]', 'active', 2, 1300000),
('Selvix Business Pro', 'website', 'Business', 350000, 'Professional business website', '["Contact forms", "SEO optimized", "Mobile responsive", "Blog system"]', 'active', 2, 700000),
('Selvix School Manager', 'app', 'Education', 900000, 'Complete school management system', '["Student records", "Grade tracking", "Parent portal", "Fee management"]', 'active', 1, 900000),
('Selvix Booking System', 'website', 'Booking', 300000, 'Appointment booking platform', '["Calendar integration", "Email notifications", "Payment gateway"]', 'active', 1, 300000),
('Selvix Property Hub', 'website', 'Real Estate', 550000, 'Property listing website', '["Advanced search", "Virtual tours", "Lead management"]', 'active', 1, 550000),
('Selvix Restaurant Site', 'website', 'Food', 450000, 'Restaurant ordering system', '["Menu management", "Online orders", "Delivery tracking"]', 'active', 1, 450000),
('Selvix E-Commerce App', 'app', 'Shop', 2500000, 'Full-featured mobile commerce app', '["Push notifications", "Multiple payment options", "Order tracking"]', 'active', 1, 2500000),
('Selvix Booking App', 'app', 'Travel', 1500000, 'Travel and hotel booking app', '["Real-time availability", "Payment processing", "Review system"]', 'active', 0, 0);

-- ============================================================
-- 4. ORDERS TABLE (Malipo)
-- ============================================================
CREATE TABLE IF NOT EXISTS orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    order_id VARCHAR(50) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    payment_method ENUM('mpesa', 'tigopesa', 'airtel', 'halopesa') NOT NULL,
    status ENUM('pending', 'success', 'failed', 'refunded') DEFAULT 'pending',
    transaction_reference VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Sample Orders
INSERT INTO orders (order_id, user_id, product_id, amount, payment_method, status, transaction_reference, created_at, completed_at) VALUES
('ORD-001-2026', 1, 1, 650000, 'mpesa', 'success', 'A1B2C3D4E5', '2026-06-15 10:30:00', '2026-06-15 10:35:00'),
('ORD-002-2026', 2, 2, 350000, 'tigopesa', 'success', 'B2C3D4E5F6', '2026-06-14 14:20:00', '2026-06-14 14:25:00'),
('ORD-003-2026', 3, 3, 900000, 'mpesa', 'success', 'C3D4E5F6G7', '2026-06-12 09:15:00', '2026-06-12 09:20:00'),
('ORD-004-2026', 3, 4, 300000, 'airtel', 'success', 'D4E5F6G7H8', '2026-06-10 16:45:00', '2026-06-10 16:50:00'),
('ORD-005-2026', 5, 2, 350000, 'mpesa', 'failed', 'E5F6G7H8I9', '2026-06-08 11:30:00', NULL),
('ORD-006-2026', 1, 5, 550000, 'halopesa', 'success', 'F6G7H8I9J0', '2026-06-05 13:00:00', '2026-06-05 13:05:00'),
('ORD-007-2026', 6, 6, 450000, 'mpesa', 'pending', 'G7H8I9J0K1', '2026-06-17 12:30:00', NULL),
('ORD-008-2026', 7, 7, 2500000, 'mpesa', 'success', 'H8I9J0K1L2', '2026-06-16 15:45:00', '2026-06-16 16:00:00'),
('ORD-009-2026', 8, 8, 1500000, 'tigopesa', 'pending', 'I9J0K1L2M3', '2026-06-17 11:20:00', NULL);

-- ============================================================
-- 5. ACTIVITY LOG TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS activity_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    admin_id INT,
    action VARCHAR(255) NOT NULL,
    description TEXT,
    entity_type VARCHAR(100),
    entity_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admin(id)
);

-- ============================================================
-- 6. NOTIFICATIONS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS notifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    recipient_type ENUM('all', 'specific_user', 'product_buyers', 'date_range') NOT NULL,
    user_ids LONGTEXT, -- JSON format for specific users
    product_id INT,
    date_from DATETIME,
    date_to DATETIME,
    channel ENUM('email', 'sms', 'both') DEFAULT 'both',
    scheduled_at TIMESTAMP NULL,
    sent_at TIMESTAMP NULL,
    status ENUM('draft', 'scheduled', 'sent') DEFAULT 'draft',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 7. PROMO CODES TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS promo_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    code VARCHAR(50) UNIQUE NOT NULL,
    discount_percentage DECIMAL(5, 2),
    discount_amount DECIMAL(15, 2),
    max_uses INT,
    used_count INT DEFAULT 0,
    product_ids LONGTEXT, -- JSON format
    valid_from DATETIME,
    valid_until DATETIME,
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 8. RESELLER/AFFILIATE TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS resellers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    referral_code VARCHAR(50) UNIQUE NOT NULL,
    commission_percentage DECIMAL(5, 2) DEFAULT 10,
    total_referrals INT DEFAULT 0,
    total_commission DECIMAL(15, 2) DEFAULT 0,
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ============================================================
-- 9. REFERRAL TRACKING TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS referrals (
    id INT PRIMARY KEY AUTO_INCREMENT,
    reseller_id INT,
    referred_user_id INT,
    order_id INT,
    commission_amount DECIMAL(15, 2),
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (reseller_id) REFERENCES resellers(id),
    FOREIGN KEY (referred_user_id) REFERENCES users(id),
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

-- ============================================================
-- 10. SETTINGS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    setting_key VARCHAR(255) UNIQUE NOT NULL,
    setting_value LONGTEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Default Settings
INSERT INTO settings (setting_key, setting_value) VALUES
('site_name', 'Selvix Technology'),
('currency', 'TZS'),
('currency_symbol', 'Tsh'),
('theme_color', '#1a56db'),
('theme_mode', 'light'),
('mpesa_api_key', 'YOUR_MPESA_KEY'),
('tigopesa_api_key', 'YOUR_TIGOPESA_KEY'),
('airtel_api_key', 'YOUR_AIRTEL_KEY'),
('support_phone', '0612929319'),
('support_email', 'support@selvix.com'),
('smtp_host', 'smtp.gmail.com'),
('smtp_port', '587'),
('smtp_email', 'your-email@gmail.com'),
('smtp_password', 'your-app-password');

-- ============================================================
-- CREATE INDEXES FOR BETTER PERFORMANCE
-- ============================================================
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_order_user ON orders(user_id);
CREATE INDEX idx_order_product ON orders(product_id);
CREATE INDEX idx_order_status ON orders(status);
CREATE INDEX idx_order_created ON orders(created_at);
CREATE INDEX idx_activity_admin ON activity_log(admin_id);
CREATE INDEX idx_product_status ON products(status);
