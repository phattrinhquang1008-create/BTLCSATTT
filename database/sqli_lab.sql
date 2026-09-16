-- ==========================================================
-- SQL Injection Vulnerable Lab Database Schema & Seed Data
-- Course: An Toan Thong Tin (Information Security)
-- Topic: SQL Injection Exploitation & Generative AI Source Analysis
-- ==========================================================

DROP DATABASE IF EXISTS sqli_lab;
CREATE DATABASE sqli_lab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sqli_lab;

-- ----------------------------------------------------------
-- 1. Table: users
-- Contains user credentials, roles, and simulated sensitive flags
-- ----------------------------------------------------------
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    secret_flag VARCHAR(100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed data for users
INSERT INTO users (id, username, password, email, role, secret_flag) VALUES
(1, 'admin', 'SuperSecretAdminP@ssw0rd2026!', 'admin@security-lab.local', 'admin', 'FLAG{sqli_admin_bypass_master_2026}'),
(2, 'manager', 'Manager@123', 'manager@security-lab.local', 'staff', 'FLAG{sqli_manager_privilege_granted}'),
(3, 'alice', 'alice_password_889', 'alice@lab.vn', 'user', 'FLAG{alice_secret_token_abc}'),
(4, 'bob', 'bob_secure_key_334', 'bob@lab.vn', 'user', 'FLAG{bob_secret_token_xyz}'),
(5, 'charlie', 'charlie999', 'charlie@lab.vn', 'user', 'FLAG{charlie_hidden_flag_777}');

-- ----------------------------------------------------------
-- 2. Table: products
-- Used in SearchServlet for Union-based, Error-based & Blind SQLi
-- ----------------------------------------------------------
DROP TABLE IF EXISTS products;
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    in_stock INT NOT NULL DEFAULT 10
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed data for products
INSERT INTO products (id, name, description, category, price, in_stock) VALUES
(1, 'Laptop Dell XPS 15', 'High performance laptop for cyber security research and software development.', 'Electronics', 1899.99, 15),
(2, 'MacBook Pro M3 Max', 'Apple flagship laptop with unified memory architecture.', 'Electronics', 2499.00, 8),
(3, 'Ubiquiti Dream Machine Pro', 'Enterprise grade security gateway & network appliance with IDS/IPS.', 'Networking', 379.50, 20),
(4, 'YubiKey 5 NFC', 'Hardware security key supporting FIDO2, WebAuthn, U2F and smart card.', 'Security Hardware', 55.00, 100),
(5, 'Hak5 WiFi Pineapple', 'Advanced wireless network auditing and penetration testing platform.', 'Security Hardware', 199.99, 12),
(6, 'Flipper Zero Multi-tool', 'Portable multi-tool device for geeks & hardware pentesters.', 'Security Hardware', 169.00, 5),
(7, 'Mechanical Keyboard Keychron Q1', 'Custom CNC aluminum mechanical keyboard with hot-swappable switches.', 'Accessories', 179.00, 30),
(8, '4K UltraWide Monitor LG 34"', 'Curved IPS display with HDR400 for multi-window productivity.', 'Electronics', 599.99, 14);

-- ----------------------------------------------------------
-- End of Schema
-- ----------------------------------------------------------
