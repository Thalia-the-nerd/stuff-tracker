/*
 * =================================================================
 * Miami Beach Senior High Robotics Team - Inventory Tracker
 * =================================================================
 * Version: 2.7.0 (User Deletion Update)
 * Author: Thalia
 * Description: A complete, single-file Node.js application to manage
 * team inventory with advanced admin controls.
 *
 * Features Included:
 * - User Authentication (Admin, Manager, User roles) with Self-Registration
 * - Full CRUD for Inventory Items with Image Uploads
 * - QR Code Generation & Scanning for quick actions
 * - Item Reservations System
 * - Location/Cabinet Management
 * - Maintenance Logging and Status
 * - Purchase Request & Approval System
 * - User-Specific Item History
 * - Advanced Reporting Dashboard with Charts
 * - Bulk CSV Data Import & Export
 * - Admin-notified Password Reset
 * - Comprehensive Audit Log
 * - Admin user moderation (Timeout/Ban)
 * - IP address tracking on login
 * - User-specific audit log and IP history view
 * - Fine-grained role management for admins
 * - **NEW**: Admins can permanently delete user accounts
 * =================================================================
 */

// 1. DEPENDENCIES & INITIAL SETUP
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const csv = require('fast-csv');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const UPLOAD_PATH = 'uploads';
const IMAGE_PATH = path.join(UPLOAD_PATH, 'images');
const CSV_PATH = path.join(UPLOAD_PATH, 'csv');

// Create upload directories if they don't exist
fs.mkdirSync(IMAGE_PATH, { recursive: true });
fs.mkdirSync(CSV_PATH, { recursive: true });

// For accurate IP address tracking behind a proxy
app.set('trust proxy', 1);

// 2. MULTER CONFIGURATION (for file uploads)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'itemImage') {
            cb(null, IMAGE_PATH);
        } else if (file.fieldname === 'csvFile') {
            cb(null, CSV_PATH);
        }
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage: storage });

// 3. DATABASE SETUP
const db = new sqlite3.Database('./mbs_robotics_inventory.db', (err) => {
    if (err) {
        console.error("Database Connection Error:", err.message);
    } else {
        console.log('Connected to the MBSH Robotics SQLite database.');
        initializeDb();
    }
});

function initializeDb() {
    db.serialize(() => {
        // --- Core Tables ---
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            student_id TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'manager', 'user')),
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'timed_out', 'banned')),
            timeout_until DATETIME
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            quantity INTEGER DEFAULT 1,
            model_number TEXT,
            serial_number TEXT UNIQUE,
            manufacturer TEXT,
            category TEXT,
            condition TEXT,
            specifications TEXT,
            location_id INTEGER,
            comment TEXT,
            image_url TEXT,
            status TEXT DEFAULT 'Available' CHECK(status IN ('Available', 'Checked Out', 'Under Maintenance')),
            checked_out_by_id INTEGER,
            last_activity_date DATETIME,
            is_kit BOOLEAN DEFAULT 0,
            FOREIGN KEY (location_id) REFERENCES locations(id),
            FOREIGN KEY (checked_out_by_id) REFERENCES users(id) ON DELETE SET NULL
        )`);

        // --- Feature-Specific Tables ---
        db.run(`CREATE TABLE IF NOT EXISTS kits (
            kit_id INTEGER,
            item_id INTEGER,
            PRIMARY KEY (kit_id, item_id),
            FOREIGN KEY (kit_id) REFERENCES items(id) ON DELETE CASCADE,
            FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            start_date DATE NOT NULL,
            end_date DATE NOT NULL,
            status TEXT DEFAULT 'Active' CHECK(status IN ('Active', 'Completed', 'Cancelled')),
            FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS maintenance_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            report_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT NOT NULL,
            resolved_date DATETIME,
            resolution_notes TEXT,
            FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS purchase_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requested_by_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            reason TEXT,
            link TEXT,
            status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Denied')),
            request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            reviewed_by_id INTEGER,
            review_date DATETIME,
            FOREIGN KEY (requested_by_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (reviewed_by_id) REFERENCES users(id) ON DELETE SET NULL
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'Completed')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            user_name TEXT,
            action TEXT NOT NULL,
            item_id INTEGER,
            item_name TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // --- Schema Integrity Check (Hotfix for existing databases) ---
        db.all("PRAGMA table_info(audit_log)", (err, columns) => {
            const hasIpAddressColumn = columns.some(col => col.name === 'ip_address');
            if (!hasIpAddressColumn) {
                console.log("Updating audit_log schema: Adding ip_address column...");
                db.run("ALTER TABLE audit_log ADD COLUMN ip_address TEXT", (alterErr) => {
                    if (alterErr) {
                        console.error("Failed to update audit_log schema:", alterErr);
                    } else {
                        console.log("Schema updated successfully.");
                    }
                });
            }
        });

        // --- Seed Initial Data ---
        db.get('SELECT * FROM users WHERE student_id = ?', ['admin'], (err, row) => {
            if (!row) {
                bcrypt.hash('adminpassword', SALT_ROUNDS, (err, hash) => {
                    db.run('INSERT INTO users (name, student_id, password, role) VALUES (?, ?, ?, ?)',
                        ['Admin', 'admin', hash, 'admin'], (err) => {
                            if (!err) console.log("Default admin created. User: admin, Pass: adminpassword");
                        });
                });
            }
        });
        db.get('SELECT * FROM locations WHERE name = ?', ['Main Cabinet'], (err, row) => {
            if(!row) db.run('INSERT INTO locations (name) VALUES (?)', ['Main Cabinet']);
        });
    });
}

// 4. HELPER FUNCTIONS
function logAction(user, action, item = null, details = '', ip = null) {
    const userId = user ? user.id : null;
    const userName = user ? user.name : 'System';
    const itemId = item ? item.id : null;
    let finalItemName = item ? item.name : null;
    
    if (itemId && !finalItemName) {
        db.get('SELECT name FROM items WHERE id = ?', [itemId], (err, row) => {
            if (row) {
                 db.run('UPDATE audit_log SET item_name = ? WHERE item_id = ? AND item_name IS NULL', [row.name, itemId]);
            }
        });
    }

    db.run('INSERT INTO audit_log (user_id, user_name, action, item_id, item_name, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [userId, userName, action, itemId, finalItemName, details, ip]);
}


// 5. MIDDLEWARE
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Serve uploaded files
app.use(session({
    secret: 'miami-beach-bots-are-the-best-bots',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Auth Middleware
const requireLogin = (req, res, next) => {
    if (!req.session.user) {
        req.session.error = 'You must be logged in to view this page.';
        return res.redirect('/login');
    }
    next();
};

const requireRole = (roles) => (req, res, next) => {
    requireLogin(req, res, () => {
        if (!roles.includes(req.session.user.role)) {
            const errorHtml = `<h1>403 - Access Denied</h1><p>You do not have the required permissions (${roles.join(', ')}) to view this page.</p><a href="/dashboard">Back to Dashboard</a>`;
            return res.status(403).send(renderPage(req, 'Access Denied', req.session.user, errorHtml));
        }
        next();
    });
};

// 6. VIEW RENDERING ENGINE (HTML Templates)
const renderPage = (req, title, user, content, messages = {}) => {
    const { error, success } = { ...req.session, ...messages };
    if (req.session) {
        delete req.session.error;
        delete req.session.success;
    }
    const userRole = user ? user.role : '';
    
    // Define navigation structure based on roles
    const navLinks = [
        { name: 'Dashboard', href: '/dashboard', roles: ['admin', 'manager', 'user'] },
        { name: 'Inventory', href: '/inventory', roles: ['admin', 'manager', 'user'] },
        { name: 'Scan QR Code', href: '/scan', roles: ['admin', 'manager', 'user'] },
        { name: 'Reservations', href: '/reservations', roles: ['admin', 'manager', 'user'] },
        { name: 'My History', href: '/my-history', roles: ['admin', 'manager', 'user'] },
        { name: 'Request Item', href: '/requests/new', roles: ['admin', 'manager', 'user'] },
    ];
    const adminLinks = [
        { name: 'Reports', href: '/reports', roles: ['admin', 'manager'] },
        { name: 'Purchase Requests', href: '/admin/requests', roles: ['admin', 'manager'] },
        { name: 'User Management', href: '/users', roles: ['admin'] },
        { name: 'Password Resets', href: '/admin/password-resets', roles: ['admin']},
        { name: 'Locations/Cabinets', href: '/locations', roles: ['admin', 'manager'] },
        { name: 'Audit Log', href: '/audit-log', roles: ['admin'] },
        { name: 'Data Management', href: '/data', roles: ['admin'] },
    ];

    const generateNavHtml = (links) => {
        return links
            .filter(link => link.roles.includes(userRole))
            .map(link => `<a href="${link.href}" class="p-3 rounded-lg sidebar-link ${title === link.name || title.startsWith(link.name) ? 'active' : ''}">${link.name}</a>`)
            .join('');
    };

    return `
        <!DOCTYPE html>
        <html lang="en" class="h-full bg-gray-100">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${title} | MBSH Robotics</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: 'Inter', sans-serif; }
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
                .sidebar-link { transition: all 0.2s; }
                .sidebar-link:hover, .sidebar-link.active { background-color: #0369a1; color: white; } /* sky-700 */
                .btn { @apply font-bold py-2 px-4 rounded-lg transition-colors; }
                .btn-primary { @apply bg-sky-600 text-white hover:bg-sky-700; }
                .btn-secondary { @apply bg-gray-200 text-gray-800 hover:bg-gray-300; }
                .btn-danger { @apply bg-red-600 text-white hover:bg-red-700; }
                .btn-warning { @apply bg-amber-500 text-white hover:bg-amber-600; }
                .card { @apply bg-white rounded-lg shadow-md p-6; }
            </style>
        </head>
        <body class="h-full">
            <div class="min-h-full flex">
                ${user ? `
                <aside class="w-64 bg-gray-800 text-gray-200 flex flex-col p-4 space-y-1 fixed h-full overflow-y-auto">
                    <h1 class="text-xl font-bold mb-4 text-white">
                        MBSH Robotics<br/>
                        <span class="text-sky-400 font-semibold">Inventory System</span>
                    </h1>
                    <nav class="flex flex-col space-y-1">
                        ${generateNavHtml(navLinks)}
                    </nav>
                    <div class="pt-4 mt-4 border-t border-gray-700">
                        <h2 class="px-3 text-xs font-semibold uppercase text-gray-400 tracking-wider">Admin</h2>
                        <nav class="flex flex-col space-y-1 mt-2">
                            ${generateNavHtml(adminLinks)}
                        </nav>
                    </div>
                    <div class="flex-grow"></div>
                    <div class="text-sm">
                        <p>Logged in as: <span class="font-semibold">${user.name}</span></p>
                        <p class="text-xs text-gray-400 capitalize">Role: ${user.role}</p>
                        <a href="/logout" class="block w-full mt-4 btn btn-danger text-center">Logout</a>
                    </div>
                </aside>` : ''}
                <div class="flex-1 ${user ? 'ml-64' : ''} p-6 md:p-10">
                    <main>
                        <h1 class="text-3xl font-bold text-gray-800 mb-6">${title}</h1>
                        ${error ? `<div class="mb-4 p-4 bg-red-100 text-red-800 border border-red-300 rounded-lg">${error}</div>` : ''}
                        ${success ? `<div class="mb-4 p-4 bg-green-100 text-green-800 border border-green-300 rounded-lg">${success}</div>` : ''}
                        ${content}
                    </main>
                </div>
            </div>
        </body>
        </html>
    `;
};

// 7. APPLICATION ROUTES
// --- Root and Dashboard ---
app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/dashboard', requireLogin, (req, res) => {
    // Complex query to get all dashboard data at once
    const sql = `
        SELECT
            (SELECT COUNT(*) FROM items) as total_items,
            (SELECT COUNT(*) FROM items WHERE status = 'Checked Out') as checked_out_items,
            (SELECT COUNT(*) FROM items WHERE status = 'Under Maintenance') as maintenance_items,
            (SELECT COUNT(*) FROM purchase_requests WHERE status = 'Pending') as pending_requests,
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT COUNT(*) FROM password_resets WHERE status = 'Pending') as pending_resets
    `;
    db.get(sql, (err, stats) => {
        if(err) {
            return res.status(500).send(renderPage(req, 'Error', req.session.user, 'Could not load dashboard data.'));
        }
        db.all(`SELECT al.*, i.name as item_name FROM audit_log al LEFT JOIN items i ON al.item_id = i.id ORDER BY timestamp DESC LIMIT 5`, (err, recent_activity) => {
            let admin_cards = '';
            if (req.session.user.role === 'admin') {
                admin_cards = `
                    <div class="card text-center bg-orange-50">
                        <a href="/admin/password-resets" class="block">
                            <h2 class="text-4xl font-bold text-orange-600">${stats.pending_resets}</h2>
                            <p class="text-gray-500">Pending Password Resets</p>
                        </a>
                    </div>
                    <div class="card text-center">
                        <a href="/users" class="block">
                            <h2 class="text-4xl font-bold text-gray-600">${stats.total_users}</h2>
                            <p class="text-gray-500">Total Users</p>
                        </a>
                    </div>
                `;
            }
            const content = `
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <div class="card text-center">
                        <a href="/inventory" class="block">
                            <h2 class="text-4xl font-bold text-sky-600">${stats.total_items}</h2>
                            <p class="text-gray-500">Total Items</p>
                        </a>
                    </div>
                    <div class="card text-center">
                        <h2 class="text-4xl font-bold text-yellow-600">${stats.checked_out_items}</h2>
                        <p class="text-gray-500">Items Checked Out</p>
                    </div>
                     <div class="card text-center">
                        <h2 class="text-4xl font-bold text-red-600">${stats.maintenance_items}</h2>
                        <p class="text-gray-500">Items in Maintenance</p>
                    </div>
                    <div class="card text-center">
                         <a href="/admin/requests" class="block">
                            <h2 class="text-4xl font-bold text-blue-600">${stats.pending_requests}</h2>
                            <p class="text-gray-500">Pending Purchase Requests</p>
                        </a>
                    </div>
                    ${admin_cards}
                </div>
                <div class="mt-8 card">
                    <h2 class="text-xl font-bold mb-4">Recent Activity</h2>
                    <ul class="divide-y divide-gray-200">
                        ${recent_activity.length > 0 ? recent_activity.map(log => `
                            <li class="py-3">
                                <p><span class="font-semibold">${log.user_name}</span> ${log.action} ${log.item_name ? `(<a href="/inventory/view/${log.item_id}" class="text-sky-600 hover:underline">${log.item_name}</a>)` : ''}</p>
                                <p class="text-sm text-gray-500">${new Date(log.timestamp).toLocaleString()}</p>
                            </li>
                        `).join('') : '<p>No recent activity.</p>'}
                    </ul>
                </div>
            `;
            res.send(renderPage(req, 'Dashboard', req.session.user, content));
        });
    });
});


// --- Authentication ---
app.get('/login', (req, res) => {
    const content = `
        <div class="max-w-md mx-auto mt-10">
            <div class="card">
                <form action="/login" method="POST">
                    <div class="mb-4">
                        <label for="student_id" class="block text-gray-700 font-bold mb-2">Student ID</label>
                        <input type="text" id="student_id" name="student_id" class="w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>
                    <div class="mb-6">
                        <label for="password" class="block text-gray-700 font-bold mb-2">Password</label>
                        <input type="password" id="password" name="password" class="w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-full">Login</button>
                </form>
                <div class="text-center mt-4">
                    <a href="/request-password-reset" class="text-sm text-sky-600 hover:underline">Forgot Password?</a>
                    <span class="mx-2 text-gray-400">|</span>
                    <a href="/register" class="text-sm text-sky-600 hover:underline">Create an Account</a>
                </div>
            </div>
        </div>
    `;
    res.send(renderPage(req, 'Login', null, content, { error: req.session.error, success: req.session.success }));
});

app.post('/login', (req, res) => {
    const { student_id, password } = req.body;
    db.get('SELECT * FROM users WHERE student_id = ?', [student_id], (err, user) => {
        if (err || !user) {
            req.session.error = "Invalid Student ID or password.";
            return res.redirect('/login');
        }

        // Check user status before attempting password verification
        if (user.status === 'banned') {
            req.session.error = "This account has been banned.";
            return res.redirect('/login');
        }
        if (user.status === 'timed_out') {
            if (new Date(user.timeout_until) > new Date()) {
                req.session.error = `This account is in a timeout until ${new Date(user.timeout_until).toLocaleString()}.`;
                return res.redirect('/login');
            } else {
                // Timeout expired, reactivate account
                db.run("UPDATE users SET status = 'active', timeout_until = NULL WHERE id = ?", [user.id]);
            }
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.user = user;
                logAction(user, 'Logged In', null, '', req.ip);
                res.redirect('/dashboard');
            } else {
                req.session.error = "Invalid Student ID or password.";
                res.redirect('/login');
            }
        });
    });
});

app.get('/register', (req, res) => {
    if (req.session.user) {
        return res.redirect('/dashboard');
    }
    const content = `
        <div class="max-w-md mx-auto mt-10">
            <div class="card">
                <h2 class="text-2xl font-bold text-center mb-4">Create Account</h2>
                <form action="/register" method="POST">
                    <div class="mb-4">
                        <label for="name" class="block text-gray-700 font-bold mb-2">Full Name</label>
                        <input type="text" id="name" name="name" class="w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>
                    <div class="mb-4">
                        <label for="student_id" class="block text-gray-700 font-bold mb-2">Student ID</label>
                        <input type="text" id="student_id" name="student_id" class="w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>
                    <div class="mb-6">
                        <label for="password" class="block text-gray-700 font-bold mb-2">Password</label>
                        <input type="password" id="password" name="password" class="w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-full">Register</button>
                </form>
                <div class="text-center mt-4">
                     <a href="/login" class="text-sm text-sky-600 hover:underline">Already have an account? Login</a>
                </div>
            </div>
        </div>
    `;
    res.send(renderPage(req, 'Register', null, content));
});

// MODIFIED /register ROUTE
app.post('/register', (req, res) => {
    const { name, student_id, password } = req.body;

    db.get('SELECT id FROM users WHERE student_id = ?', [student_id], (err, row) => {
        if(row) {
            req.session.error = "A user with that Student ID already exists.";
            return res.redirect('/register');
        }

        bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
            if (err) {
                req.session.error = "An error occurred during registration.";
                return res.redirect('/register');
            }
            
            const sql = 'INSERT INTO users (name, student_id, password, role) VALUES (?, ?, ?, ?)';
            db.run(sql, [name, student_id, hash, 'user'], function(err) {
                if (err) {
                    req.session.error = "Failed to create account.";
                    res.redirect('/register');
                } else {
                    const newUserId = this.lastID;
                    const newUser = {
                        id: newUserId,
                        name: name,
                        student_id: student_id,
                        role: 'user',
                        status: 'active' 
                    };

                    logAction(newUser, 'User Registered', null, `New user: ${name} (${student_id})`, req.ip);
                    req.session.user = newUser; // Auto-login
                    res.redirect('/dashboard');
                }
            });
        });
    });
});

app.get('/logout', (req, res) => {
    logAction(req.session.user, 'Logged Out', null, '', req.ip);
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// --- QR Code Routes ---
app.get('/qr/:itemId', requireLogin, (req, res) => {
    const url = `${req.protocol}://${req.get('host')}/quick-action/${req.params.itemId}`;
    QRCode.toDataURL(url, (err, dataUrl) => {
        if (err) {
            res.status(500).send("Error generating QR code.");
        } else {
            res.send(`<img src="${dataUrl}" alt="QR Code">`);
        }
    });
});

app.get('/scan', requireLogin, (req, res) => {
    const content = `
        <div class="card max-w-lg mx-auto">
            <h2 class="text-xl font-bold mb-4">Scan or Enter Item ID</h2>
            <p class="mb-4 text-gray-600">Use your device's camera to scan an item's QR code, or manually enter the ID number found on the item's label.</p>
            <form action="/scan-handler" method="POST">
                <div class="mb-4">
                    <label for="itemId" class="block text-gray-700 font-bold mb-2">Item ID</label>
                    <input type="number" name="itemId" id="itemId" class="w-full p-2 border border-gray-300 rounded-lg" required>
                </div>
                <button type="submit" class="btn btn-primary w-full">Go to Item</button>
            </form>
        </div>
    `;
    res.send(renderPage(req, 'Scan QR Code', req.session.user, content));
});

app.post('/scan-handler', requireLogin, (req, res) => {
    const { itemId } = req.body;
    res.redirect(`/quick-action/${itemId}`);
});

app.get('/quick-action/:id', requireLogin, (req, res) => {
    db.get(`SELECT i.*, u.name as checked_out_by_name 
            FROM items i 
            LEFT JOIN users u ON i.checked_out_by_id = u.id
            WHERE i.id = ?`, [req.params.id], (err, item) => {
        if (!item) {
            req.session.error = "Item not found.";
            return res.redirect('/inventory');
        }
        let actionButton = '';
        if (item.status === 'Available') {
            actionButton = `<form action="/inventory/checkout/${item.id}" method="POST"><button type="submit" class="btn btn-primary w-full text-lg">Check Out</button></form>`;
        } else if (item.status === 'Checked Out' && (item.checked_out_by_id === req.session.user.id || req.session.user.role !== 'user')) {
             actionButton = `<form action="/inventory/checkin/${item.id}" method="POST"><button type="submit" class="btn btn-secondary w-full text-lg">Check In</button></form>`;
        }

        const content = `
            <div class="card max-w-2xl mx-auto">
                <div class="flex flex-col md:flex-row gap-6">
                    <div class="md:w-1/3">
                        <img src="${item.image_url || '/uploads/images/placeholder.png'}" alt="${item.name}" class="w-full h-auto rounded-lg shadow-md">
                    </div>
                    <div class="md:w-2/3">
                        <h2 class="text-2xl font-bold">${item.name}</h2>
                        <p class="text-gray-500 mb-4">S/N: ${item.serial_number || 'N/A'}</p>
                        <p class="mb-2"><strong>Status:</strong> <span class="font-semibold px-2 py-1 rounded-full text-sm
                            ${item.status === 'Available' ? 'bg-green-100 text-green-800' : ''}
                            ${item.status === 'Checked Out' ? 'bg-yellow-100 text-yellow-800' : ''}
                            ${item.status === 'Under Maintenance' ? 'bg-red-100 text-red-800' : ''}
                        ">${item.status}</span></p>
                        ${item.status === 'Checked Out' ? `<p class="mb-4"><strong>Checked out by:</strong> ${item.checked_out_by_name}</p>` : ''}
                        <div class="mt-6">
                            ${actionButton}
                        </div>
                         <div class="text-center mt-4">
                            <a href="/inventory/view/${item.id}" class="text-sky-600 hover:underline">View Full Details</a>
                        </div>
                    </div>
                </div>
            </div>
        `;
        res.send(renderPage(req, 'Quick Action', req.session.user, content));
    });
});


// --- Inventory Management (Full CRUD) ---
app.get('/inventory', requireLogin, (req,res) => {
    db.all("SELECT i.*, l.name as location_name FROM items i LEFT JOIN locations l ON i.location_id = l.id ORDER BY i.name", (err, items) => {
        if(err) { /* handle error */ }
        const itemsHtml = items.map(item => `
            <tr class="border-b hover:bg-gray-50">
                <td class="py-2 px-4">${item.id}</td>
                <td class="py-2 px-4 font-semibold text-sky-700">${item.name}</td>
                <td class="py-2 px-4">${item.category || 'N/A'}</td>
                <td class="py-2 px-4">${item.location_name || 'N/A'}</td>
                <td class="py-2 px-4">
                     <span class="font-semibold px-2 py-1 rounded-full text-xs
                        ${item.status === 'Available' ? 'bg-green-100 text-green-800' : ''}
                        ${item.status === 'Checked Out' ? 'bg-yellow-100 text-yellow-800' : ''}
                        ${item.status === 'Under Maintenance' ? 'bg-red-100 text-red-800' : ''}
                    ">${item.status}</span>
                </td>
                <td class="py-2 px-4">
                    <a href="/inventory/view/${item.id}" class="text-sky-600 hover:underline">Details</a>
                </td>
            </tr>
        `).join('');
        const content = `
        <div class="flex justify-between items-center mb-4">
            <div></div>
            <a href="/inventory/add" class="btn btn-primary">Add New Item</a>
        </div>
        <div class="card overflow-x-auto">
            <table class="w-full text-left">
                <thead><tr class="border-b-2">
                    <th class="py-2 px-4">ID</th><th class="py-2 px-4">Name</th><th class="py-2 px-4">Category</th><th class="py-2 px-4">Location</th><th class="py-2 px-4">Status</th><th class="py-2 px-4">Actions</th>
                </tr></thead>
                <tbody>${itemsHtml}</tbody>
            </table>
        </div>
        `;
        res.send(renderPage(req, 'Inventory', req.session.user, content));
    });
});

app.get('/inventory/add', requireRole(['admin', 'manager']), (req, res) => {
    db.all('SELECT * FROM locations', (err, locations) => {
        const locationsOptions = locations.map(l => `<option value="${l.id}">${l.name}</option>`).join('');
        const content = `
            <div class="card max-w-4xl mx-auto">
                <form action="/inventory/add" method="POST" enctype="multipart/form-data">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div><label class="block">Name*</label><input type="text" name="name" class="w-full p-2 border rounded" required></div>
                        <div><label class="block">Category</label><input type="text" name="category" class="w-full p-2 border rounded"></div>
                        <div><label class="block">Model Number</label><input type="text" name="model_number" class="w-full p-2 border rounded"></div>
                        <div><label class="block">Serial Number</label><input type="text" name="serial_number" class="w-full p-2 border rounded"></div>
                        <div><label class="block">Manufacturer/Supplier</label><input type="text" name="manufacturer" class="w-full p-2 border rounded"></div>
                        <div><label class="block">Condition</label><input type="text" name="condition" class="w-full p-2 border rounded"></div>
                        <div><label class="block">Location</label><select name="location_id" class="w-full p-2 border rounded">${locationsOptions}</select></div>
                        <div><label class="block">Quantity</label><input type="number" name="quantity" value="1" class="w-full p-2 border rounded"></div>
                        <div class="md:col-span-2"><label class="block">Specifications</label><textarea name="specifications" class="w-full p-2 border rounded"></textarea></div>
                        <div class="md:col-span-2"><label class="block">Comment</label><textarea name="comment" class="w-full p-2 border rounded"></textarea></div>
                        <div><label class="block">Image</label><input type="file" name="itemImage" class="w-full p-2 border rounded"></div>
                    </div>
                    <div class="mt-6"><button type="submit" class="btn btn-primary">Add Item</button></div>
                </form>
            </div>
        `;
        res.send(renderPage(req, 'Add New Item', req.session.user, content));
    });
});

app.post('/inventory/add', requireRole(['admin', 'manager']), upload.single('itemImage'), (req, res) => {
    const { name, quantity, model_number, serial_number, manufacturer, category, condition, specifications, location_id, comment } = req.body;
    const imageUrl = req.file ? `/uploads/images/${req.file.filename}` : null;
    
    const sql = `INSERT INTO items (name, quantity, model_number, serial_number, manufacturer, category, condition, specifications, location_id, comment, image_url, last_activity_date)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`;
    
    db.run(sql, [name, quantity, model_number, serial_number, manufacturer, category, condition, specifications, location_id, comment, imageUrl], function(err) {
        if (err) {
            req.session.error = `Failed to add item. Serial number might already exist. Error: ${err.message}`;
            res.redirect('/inventory/add');
        } else {
            const newItem = { id: this.lastID, name: name };
            logAction(req.session.user, 'Created Item', newItem, '', req.ip);
            req.session.success = "Item added successfully.";
            res.redirect('/inventory');
        }
    });
});

app.get('/inventory/view/:id', requireLogin, async (req, res) => {
    const itemId = req.params.id;
    db.get(`SELECT i.*, l.name as location_name, u.name as checked_out_by_name 
            FROM items i 
            LEFT JOIN locations l ON i.location_id = l.id
            LEFT JOIN users u ON i.checked_out_by_id = u.id
            WHERE i.id = ?`, [itemId], async (err, item) => {
        if(err || !item) {
            req.session.error = "Item not found.";
            return res.redirect('/inventory');
        }
        
        db.all('SELECT ml.*, u.name as reporter_name FROM maintenance_log ml JOIN users u ON ml.user_id = u.id WHERE item_id = ? ORDER BY report_date DESC', [itemId], async (err, maintenance_logs) => {

            const qrCodeUrl = await QRCode.toDataURL(`${req.protocol}://${req.get('host')}/quick-action/${itemId}`);

            let adminActions = '';
            if(req.session.user.role !== 'user') {
                adminActions = `<div class="flex gap-2"><a href="/inventory/edit/${item.id}" class="btn btn-secondary">Edit Item</a>
                <form action="/inventory/delete/${item.id}" method="POST" onsubmit="return confirm('Are you sure you want to permanently delete this item?');">
                    <button type="submit" class="btn btn-danger">Delete</button>
                </form></div>`;
            }
            
            let actionBox = '';
            if (item.status === 'Available') {
                actionBox = `<form action="/inventory/checkout/${item.id}" method="POST"><button type="submit" class="btn btn-primary w-full">Check Out</button></form>`;
            } else if (item.status === 'Checked Out') {
                actionBox = `<form action="/inventory/checkin/${item.id}" method="POST"><button type="submit" class="btn btn-secondary w-full">Check In</button></form>`;
            }
            
            let maintenanceBox = `<div class="mt-4">
                <h4 class="font-bold">Report an Issue</h4>
                <form action="/maintenance/report/${item.id}" method="POST">
                    <textarea name="description" class="w-full p-2 border rounded" placeholder="Describe the issue..." required></textarea>
                    <button type="submit" class="btn btn-danger w-full mt-2">Submit Report</button>
                </form>
            </div>`;

            const maintenanceHistory = maintenance_logs.length > 0 ? `
                <div class="mt-4 pt-4 border-t">
                    <h3 class="font-bold">Maintenance History</h3>
                    <ul class="divide-y">${maintenance_logs.map(log => `
                        <li class="py-2">
                            <p><strong>${log.description}</strong> - Reported by ${log.reporter_name}</p>
                            <p class="text-sm text-gray-500">${new Date(log.report_date).toLocaleString()}</p>
                            ${log.resolved_date ? `<p class="text-sm text-green-600">Resolved: ${log.resolution_notes}</p>` : ''}
                        </li>
                    `).join('')}</ul>
                </div>` : '';


            const content = `
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div class="lg:col-span-2">
                        <div class="card">
                            <div class="flex justify-between items-start">
                                 <h2 class="text-2xl font-bold">${item.name}</h2>
                                 ${adminActions}
                            </div>
                            <p class="text-gray-500 mb-4">Category: ${item.category || 'N/A'}</p>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <p><strong>Status:</strong> <span class="font-semibold px-2 py-1 rounded-full text-sm
                                    ${item.status === 'Available' ? 'bg-green-100 text-green-800' : ''}
                                    ${item.status === 'Checked Out' ? 'bg-yellow-100 text-yellow-800' : ''}
                                    ${item.status === 'Under Maintenance' ? 'bg-red-100 text-red-800' : ''}
                                ">${item.status}</span></p>
                                ${item.status === 'Checked Out' ? `<p><strong>Checked out by:</strong> ${item.checked_out_by_name}</p>` : ''}
                                <p><strong>Model:</strong> ${item.model_number || 'N/A'}</p>
                                <p><strong>Serial:</strong> ${item.serial_number || 'N/A'}</p>
                                <p><strong>Location:</strong> ${item.location_name || 'N/A'}</p>
                                <p><strong>Manufacturer:</strong> ${item.manufacturer || 'N/A'}</p>
                            </div>
                            <div class="mt-4 pt-4 border-t">
                                 <h3 class="font-bold">Specifications</h3>
                                 <p class="text-gray-700 whitespace-pre-wrap">${item.specifications || 'None'}</p>
                            </div>
                             <div class="mt-4 pt-4 border-t">
                                 <h3 class="font-bold">Comments</h3>
                                 <p class="text-gray-700 whitespace-pre-wrap">${item.comment || 'None'}</p>
                            </div>
                            ${maintenanceHistory}
                        </div>
                    </div>
                    <div>
                        <div class="card text-center">
                            <h3 class="font-bold mb-2">Item QR Code</h3>
                             <img src="${qrCodeUrl}" alt="QR Code" class="mx-auto max-w-full h-auto">
                            <a href="/qr/${item.id}" target="_blank" class="text-sm text-sky-600 hover:underline mt-2 inline-block">Open in new tab</a>
                        </div>
                         <div class="card mt-6">
                             <h3 class="font-bold mb-2">Actions</h3>
                             ${actionBox}
                             ${maintenanceBox}
                         </div>
                    </div>
                </div>
            `;
            res.send(renderPage(req, item.name, req.session.user, content));
        });
    });
});

app.get('/inventory/edit/:id', requireRole(['admin', 'manager']), (req, res) => {
    const itemId = req.params.id;
    db.get('SELECT * FROM items WHERE id = ?', [itemId], (err, item) => {
        if(err || !item) {
            req.session.error = "Item not found.";
            return res.redirect('/inventory');
        }
        db.all('SELECT * FROM locations', (err, locations) => {
            const locationsOptions = locations.map(l => `<option value="${l.id}" ${item.location_id === l.id ? 'selected' : ''}>${l.name}</option>`).join('');
            const content = `
                <div class="card max-w-4xl mx-auto">
                    <form action="/inventory/edit/${itemId}" method="POST" enctype="multipart/form-data">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div><label class="block">Name*</label><input type="text" name="name" value="${item.name}" class="w-full p-2 border rounded" required></div>
                            <div><label class="block">Category</label><input type="text" name="category" value="${item.category || ''}" class="w-full p-2 border rounded"></div>
                            <div><label class="block">Model Number</label><input type="text" name="model_number" value="${item.model_number || ''}" class="w-full p-2 border rounded"></div>
                            <div><label class="block">Serial Number</label><input type="text" name="serial_number" value="${item.serial_number || ''}" class="w-full p-2 border rounded"></div>
                            <div><label class="block">Manufacturer/Supplier</label><input type="text" name="manufacturer" value="${item.manufacturer || ''}" class="w-full p-2 border rounded"></div>
                            <div><label class="block">Condition</label><input type="text" name="condition" value="${item.condition || ''}" class="w-full p-2 border rounded"></div>
                            <div><label class="block">Location</label><select name="location_id" class="w-full p-2 border rounded">${locationsOptions}</select></div>
                            <div><label class="block">Quantity</label><input type="number" name="quantity" value="${item.quantity}" class="w-full p-2 border rounded"></div>
                            <div class="md:col-span-2"><label class="block">Specifications</label><textarea name="specifications" class="w-full p-2 border rounded">${item.specifications || ''}</textarea></div>
                            <div class="md:col-span-2"><label class="block">Comment</label><textarea name="comment" class="w-full p-2 border rounded">${item.comment || ''}</textarea></div>
                            <div>
                                <label class="block">Image</label>
                                <input type="file" name="itemImage" class="w-full p-2 border rounded">
                                <p class="text-sm text-gray-500">Current: <a href="${item.image_url || '#'}" class="text-sky-600">${item.image_url ? 'View Image' : 'None'}</a></p>
                            </div>
                        </div>
                        <div class="mt-6"><button type="submit" class="btn btn-primary">Save Changes</button></div>
                    </form>
                </div>
            `;
            res.send(renderPage(req, `Edit: ${item.name}`, req.session.user, content));
        });
    });
});

app.post('/inventory/edit/:id', requireRole(['admin', 'manager']), upload.single('itemImage'), (req, res) => {
    const itemId = req.params.id;
    const { name, quantity, model_number, serial_number, manufacturer, category, condition, specifications, location_id, comment } = req.body;
    
    let imageUrlSql = '';
    let imageUrlParams = [];
    if (req.file) {
        imageUrlSql = ', image_url = ?';
        imageUrlParams.push(`/uploads/images/${req.file.filename}`);
    }

    const sql = `UPDATE items SET 
        name = ?, quantity = ?, model_number = ?, serial_number = ?, manufacturer = ?, 
        category = ?, condition = ?, specifications = ?, location_id = ?, comment = ?
        ${imageUrlSql} 
        WHERE id = ?`;
    
    const params = [name, quantity, model_number, serial_number, manufacturer, category, condition, specifications, location_id, comment, ...imageUrlParams, itemId];

    db.run(sql, params, function(err) {
        if (err) {
            req.session.error = `Failed to update item. Error: ${err.message}`;
            res.redirect(`/inventory/edit/${itemId}`);
        } else {
            logAction(req.session.user, 'Updated Item', { id: itemId, name: name }, '', req.ip);
            req.session.success = "Item updated successfully.";
            res.redirect(`/inventory/view/${itemId}`);
        }
    });
});

app.post('/inventory/delete/:id', requireRole(['admin']), (req, res) => {
    const itemId = req.params.id;
    db.get('SELECT name, image_url FROM items WHERE id = ?', [itemId], (err, item) => {
         if (err || !item) {
            req.session.error = "Item not found.";
            return res.redirect('/inventory');
        }
        db.run('DELETE FROM items WHERE id = ?', [itemId], function(err) {
            if (err) {
                req.session.error = `Failed to delete item. Error: ${err.message}`;
                res.redirect(`/inventory/view/${itemId}`);
            } else {
                if (item.image_url) {
                    fs.unlink(path.join(__dirname, item.image_url), (unlinkErr) => {
                        if (unlinkErr) console.error("Error deleting image file:", unlinkErr);
                    });
                }
                logAction(req.session.user, 'Deleted Item', { id: itemId, name: item.name }, '', req.ip);
                req.session.success = `Item "${item.name}" has been permanently deleted.`;
                res.redirect('/inventory');
            }
        });
    });
});

// --- Check-in / Check-out Logic ---
app.post('/inventory/checkout/:id', requireLogin, (req, res) => {
    const itemId = req.params.id;
    const userId = req.session.user.id;
    const sql = `UPDATE items SET status = 'Checked Out', checked_out_by_id = ?, last_activity_date = CURRENT_TIMESTAMP WHERE id = ? AND status = 'Available'`;
    db.run(sql, [userId, itemId], function(err) {
        if (err || this.changes === 0) {
            req.session.error = "Failed to check out item. It may already be checked out or in maintenance.";
        } else {
            req.session.success = "Item checked out successfully!";
            logAction(req.session.user, 'Checked Out Item', { id: itemId }, '', req.ip);
        }
        res.redirect(req.get('referer') || '/inventory');
    });
});

app.post('/inventory/checkin/:id', requireLogin, (req, res) => {
    const itemId = req.params.id;
    const userId = req.session.user.id;
    // Admin/manager can check in any item, users only their own
    const condition = req.session.user.role === 'user' ? `AND checked_out_by_id = ${userId}` : '';
    const sql = `UPDATE items SET status = 'Available', checked_out_by_id = NULL, last_activity_date = CURRENT_TIMESTAMP WHERE id = ? AND status = 'Checked Out' ${condition}`;
    db.run(sql, [itemId], function(err) {
        if (err || this.changes === 0) {
            req.session.error = "Failed to check in item. You may not have it checked out or it is not currently checked out.";
        } else {
            req.session.success = "Item checked in successfully!";
            logAction(req.session.user, 'Checked In Item', { id: itemId }, '', req.ip);
        }
        res.redirect(req.get('referer') || '/inventory');
    });
});

// --- Maintenance ---
app.post('/maintenance/report/:id', requireLogin, (req, res) => {
    const itemId = req.params.id;
    const { description } = req.body;
    db.run('INSERT INTO maintenance_log (item_id, user_id, description) VALUES (?, ?, ?)', [itemId, req.session.user.id, description], function(err) {
        if (err) {
            req.session.error = "Failed to report issue.";
        } else {
            db.run("UPDATE items SET status = 'Under Maintenance' WHERE id = ?", [itemId]);
            logAction(req.session.user, 'Reported Maintenance', { id: itemId }, description, req.ip);
            req.session.success = "Maintenance issue reported. Item status has been updated.";
        }
        res.redirect(`/inventory/view/${itemId}`);
    });
});


// --- Admin: User Management ---
app.get('/users', requireRole(['admin']), (req, res) => {
    db.all("SELECT * FROM users", (err, users) => {
        const usersHtml = users.map(u => {
            let statusBadge = '';
            switch(u.status) {
                case 'active': statusBadge = '<span class="bg-green-100 text-green-800 text-xs font-medium px-2.5 py-0.5 rounded-full">Active</span>'; break;
                case 'timed_out': statusBadge = `<span class="bg-yellow-100 text-yellow-800 text-xs font-medium px-2.5 py-0.5 rounded-full">Timed Out</span>`; break;
                case 'banned': statusBadge = '<span class="bg-red-100 text-red-800 text-xs font-medium px-2.5 py-0.5 rounded-full">Banned</span>'; break;
            }
            // Prevent admins from moderating other admins
            let actions = u.role === 'admin' ? 'N/A' : `
                 <a href="/users/view/${u.id}" class="text-sky-600 hover:underline">Details</a>
            `;
            
            return `
             <tr class="border-b">
                <td class="py-2 px-4">${u.name}</td>
                <td class="py-2 px-4">${u.student_id}</td>
                <td class="py-2 px-4 capitalize">${u.role}</td>
                <td class="py-2 px-4">${statusBadge}</td>
                <td class="py-2 px-4">${actions}</td>
            </tr>
            `;
        }).join('');

        const content = `
        <div class="card">
             <h2 class="text-xl font-bold mb-4">User Accounts</h2>
             <div class="overflow-x-auto">
                 <table class="w-full text-left">
                    <thead><tr class="border-b-2">
                        <th class="py-2 px-4">Name</th><th class="py-2 px-4">Student ID</th><th class="py-2 px-4">Role</th><th class="py-2 px-4">Status</th><th class="py-2 px-4">Actions</th>
                    </tr></thead>
                    <tbody>${usersHtml}</tbody>
                </table>
             </div>
        </div>
        `;
        res.send(renderPage(req, 'User Management', req.session.user, content));
    });
});

app.get('/users/view/:id', requireRole(['admin']), (req, res) => {
    const userId = req.params.id;
    db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {
        if(err || !user) {
            req.session.error = "User not found.";
            return res.redirect('/users');
        }

        db.all("SELECT * FROM audit_log WHERE user_id = ? ORDER BY timestamp DESC", [userId], (err, logs) => {
            db.all("SELECT DISTINCT ip_address FROM audit_log WHERE user_id = ? AND ip_address IS NOT NULL", [userId], (err, ips) => {
                
                const logsHtml = logs.map(l => `
                    <tr class="border-b">
                        <td class="p-2">${new Date(l.timestamp).toLocaleString()}</td>
                        <td class="p-2">${l.action}</td>
                        <td class="p-2">${l.item_name || 'N/A'}</td>
                        <td class="p-2">${l.ip_address || 'N/A'}</td>
                    </tr>
                `).join('');

                let moderationForm = '';
                let dangerZone = '';
                if(user.role !== 'admin') {
                    if (user.status === 'active') {
                        moderationForm = `
                            <form action="/users/timeout/${user.id}" method="POST" class="mb-2">
                                <label>Duration (hours)</label>
                                <input type="number" name="duration" value="24" class="p-1 border rounded">
                                <button type="submit" class="btn btn-warning">Timeout</button>
                            </form>
                            <form action="/users/ban/${user.id}" method="POST" onsubmit="return confirm('Ban this user? This is permanent.')">
                                <button type="submit" class="btn btn-danger">Ban</button>
                            </form>
                        `;
                    } else {
                         moderationForm = `
                            <form action="/users/reactivate/${user.id}" method="POST">
                                <button type="submit" class="btn btn-primary">Reactivate</button>
                            </form>
                        `;
                    }
                    // Add Delete User form to the Danger Zone
                    dangerZone = `
                        <div class="card mt-6 border-t-4 border-red-500">
                            <h2 class="text-xl font-bold mb-4 text-red-700">Danger Zone</h2>
                            <form action="/users/delete/${user.id}" method="POST" onsubmit="return confirm('Are you sure you want to permanently delete this user? This action cannot be undone.');">
                                <button type="submit" class="btn btn-danger w-full">Delete User Permanently</button>
                            </form>
                        </div>
                    `;
                }
                
                let roleManagementForm = '';
                if(user.role !== 'admin') {
                    roleManagementForm = `
                        <div class="card mt-6">
                            <h2 class="text-xl font-bold mb-4">Change Role</h2>
                            <form action="/users/update-role/${user.id}" method="POST">
                                <select name="role" class="w-full p-2 border rounded mb-2">
                                    <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
                                    <option value="manager" ${user.role === 'manager' ? 'selected' : ''}>Manager</option>
                                </select>
                                <button type="submit" class="btn btn-primary w-full">Set Role</button>
                            </form>
                        </div>
                    `;
                }

                const content = `
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div class="lg:col-span-2">
                        <div class="card">
                            <h2 class="text-xl font-bold mb-4">User Audit Log</h2>
                            <table class="w-full text-sm text-left">
                                <thead><tr class="border-b-2">
                                    <th class="p-2">Timestamp</th><th class="p-2">Action</th><th class="p-2">Item</th><th class="p-2">IP</th>
                                </tr></thead>
                                <tbody>${logsHtml}</tbody>
                            </table>
                        </div>
                    </div>
                    <div>
                        <div class="card">
                             <h2 class="text-xl font-bold mb-4">User Details</h2>
                             <p><strong>Name:</strong> ${user.name}</p>
                             <p><strong>Student ID:</strong> ${user.student_id}</p>
                             <p><strong>Role:</strong> ${user.role}</p>
                             <p><strong>Status:</strong> ${user.status}</p>
                             ${user.status === 'timed_out' ? `<p><strong>Timeout Ends:</strong> ${new Date(user.timeout_until).toLocaleString()}</p>` : ''}
                        </div>
                        <div class="card mt-6">
                            <h2 class="text-xl font-bold mb-4">Moderation</h2>
                            ${moderationForm}
                        </div>
                        ${roleManagementForm}
                        <div class="card mt-6">
                            <h2 class="text-xl font-bold mb-4">Known IP Addresses</h2>
                            <ul class="list-disc list-inside">
                                ${ips.map(ip => `<li>${ip.ip_address}</li>`).join('')}
                            </ul>
                        </div>
                        ${dangerZone}
                    </div>
                </div>
                `;
                res.send(renderPage(req, `User Details: ${user.name}`, req.session.user, content));
            });
        });
    });
});

app.post('/users/update-role/:id', requireRole(['admin']), (req, res) => {
    const userId = req.params.id;
    const { role } = req.body;
    if (!['user', 'manager'].includes(role)) {
        req.session.error = "Invalid role selected.";
        return res.redirect(`/users/view/${userId}`);
    }
    
    db.get("SELECT role FROM users WHERE id = ?", [userId], (err, userToUpdate) => {
        if (err || !userToUpdate) {
            req.session.error = "User not found.";
            return res.redirect('/users');
        }
        if (userToUpdate.role === 'admin') {
            req.session.error = "Cannot change the role of an administrator.";
            return res.redirect('/users');
        }
        db.run("UPDATE users SET role = ? WHERE id = ?", [role, userId], function(err) {
            if (err) {
                req.session.error = "Failed to update user role.";
            } else {
                logAction(req.session.user, 'Updated User Role', null, `Set User ID ${userId} to ${role}`, req.ip);
                req.session.success = "User role updated successfully.";
            }
            res.redirect(`/users/view/${userId}`);
        });
    });
});

app.post('/users/timeout/:id', requireRole(['admin']), (req, res) => {
    const userId = req.params.id;
    const durationHours = parseInt(req.body.duration, 10) || 24;
    const timeoutUntil = new Date();
    timeoutUntil.setHours(timeoutUntil.getHours() + durationHours);

    db.run("UPDATE users SET status = 'timed_out', timeout_until = ? WHERE id = ? AND role != 'admin'", [timeoutUntil, userId], function(err) {
        if(err) { req.session.error = "Failed to time out user."; }
        else {
            logAction(req.session.user, 'Timed Out User', null, `User ID: ${userId} for ${durationHours} hours.`, req.ip);
            req.session.success = "User has been placed in timeout.";
        }
        res.redirect(`/users/view/${userId}`);
    });
});

app.post('/users/ban/:id', requireRole(['admin']), (req, res) => {
    const userId = req.params.id;
    db.run("UPDATE users SET status = 'banned' WHERE id = ? AND role != 'admin'", [userId], function(err) {
         if(err) { req.session.error = "Failed to ban user."; }
         else {
             logAction(req.session.user, 'Banned User', null, `User ID: ${userId}`, req.ip);
             req.session.success = "User has been banned.";
         }
        res.redirect(`/users/view/${userId}`);
    });
});

app.post('/users/reactivate/:id', requireRole(['admin']), (req, res) => {
    const userId = req.params.id;
    db.run("UPDATE users SET status = 'active', timeout_until = NULL WHERE id = ?", [userId], function(err) {
         if(err) { req.session.error = "Failed to reactivate user."; }
         else {
             logAction(req.session.user, 'Reactivated User', null, `User ID: ${userId}`, req.ip);
             req.session.success = "User has been reactivated.";
         }
        res.redirect(`/users/view/${userId}`);
    });
});

// NEW ROUTE: Delete User
app.post('/users/delete/:id', requireRole(['admin']), (req, res) => {
    const userIdToDelete = req.params.id;
    const adminUserId = req.session.user.id;

    // Safety check: Admin cannot delete themselves
    if (userIdToDelete == adminUserId) {
        req.session.error = "You cannot delete your own account.";
        return res.redirect('/users');
    }

    db.get('SELECT * FROM users WHERE id = ?', [userIdToDelete], (err, user) => {
        if (err || !user) {
            req.session.error = "User not found.";
            return res.redirect('/users');
        }

        // Safety check: Do not delete other admins
        if (user.role === 'admin') {
            req.session.error = "Administrators cannot be deleted.";
            return res.redirect(`/users/view/${userIdToDelete}`);
        }

        // Safety check: Verify the user does not have any items currently checked out
        db.get('SELECT id, name FROM items WHERE checked_out_by_id = ?', [userIdToDelete], (err, item) => {
            if (err) {
                req.session.error = "Database error while checking for checked-out items.";
                return res.redirect(`/users/view/${userIdToDelete}`);
            }
            if (item) {
                req.session.error = `Cannot delete user. They still have item "${item.name}" checked out. Please check in all items first.`;
                return res.redirect(`/users/view/${userIdToDelete}`);
            }

            // Proceed with deletion
            db.run('DELETE FROM users WHERE id = ?', [userIdToDelete], function(err) {
                if (err) {
                    req.session.error = `Failed to delete user. Error: ${err.message}`;
                    return res.redirect(`/users/view/${userIdToDelete}`);
                }
                logAction(req.session.user, 'Deleted User', null, `Deleted user: ${user.name} (ID: ${userIdToDelete})`, req.ip);
                req.session.success = `User "${user.name}" has been permanently deleted.`;
                res.redirect('/users');
            });
        });
    });
});


app.get('/request-password-reset', (req, res) => {
    const content = `<div class="card max-w-md mx-auto">
        <h2 class="text-xl font-bold mb-4">Request Password Reset</h2>
        <p class="mb-4">Enter your Student ID. If it exists, an admin will be notified to reset your password.</p>
        <form action="/request-password-reset" method="POST">
             <div class="mb-4">
                <label class="block text-gray-700">Student ID</label>
                <input type="text" name="student_id" class="w-full p-2 border rounded" required>
            </div>
            <button type="submit" class="btn btn-primary w-full">Submit Request</button>
            <div class="text-center mt-4">
                <a href="/login" class="text-sm text-sky-600 hover:underline">Back to Login</a>
            </div>
        </form>
    </div>`;
    res.send(renderPage(req, 'Password Reset', null, content));
});

app.post('/request-password-reset', (req, res) => {
    const { student_id } = req.body;
    db.get('SELECT id FROM users WHERE student_id = ?', [student_id], (err, user) => {
        if(user) {
            // Avoid creating duplicate pending requests
            db.get('SELECT id FROM password_resets WHERE user_id = ? AND status = ?', [user.id, 'Pending'], (err, existing) => {
                if(!existing) {
                    db.run('INSERT INTO password_resets (user_id, status) VALUES (?, ?)', [user.id, 'Pending']);
                }
            });
        }
        // Always show a generic success message to prevent user enumeration (leaking which student IDs are valid)
        req.session.success = "If your account exists, a password reset request has been sent to the administrator.";
        res.redirect('/login');
    });
});

// --- FULLY IMPLEMENTED ROUTES ---

app.get('/reservations', requireLogin, (req, res) => {
    const today = new Date();
    const monthQuery = req.query.month;
    const yearQuery = req.query.year;

    const month = (monthQuery !== undefined && !isNaN(parseInt(monthQuery, 10))) ? parseInt(monthQuery, 10) : today.getMonth();
    const year = (yearQuery !== undefined && !isNaN(parseInt(yearQuery, 10))) ? parseInt(yearQuery, 10) : today.getFullYear();


    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const monthName = firstDay.toLocaleString('default', { month: 'long' });

    const prevMonth = month === 0 ? 11 : month - 1;
    const prevYear = month === 0 ? year - 1 : year;
    const nextMonth = month === 11 ? 0 : month + 1;
    const nextYear = month === 11 ? year + 1 : year;

    const sql = `
        SELECT r.id, r.start_date, r.end_date, i.name as item_name, u.name as user_name, r.user_id
        FROM reservations r
        JOIN items i ON r.item_id = i.id
        JOIN users u ON r.user_id = u.id
        WHERE r.status = 'Active' AND
              ((start_date BETWEEN ? AND ?) OR (end_date BETWEEN ? AND ?))
    `;
    const startDateStr = `${year}-${String(month + 1).padStart(2, '0')}-01`;
    const endDateStr = `${year}-${String(month + 1).padStart(2, '0')}-${lastDay.getDate()}`;

    db.all(sql, [startDateStr, endDateStr, startDateStr, endDateStr], (err, reservations) => {
        db.all('SELECT id, name FROM items ORDER BY name', (err, items) => {

            let calendarHtml = '';
            const daysInMonth = lastDay.getDate();
            const startingDay = firstDay.getDay();

            for (let i = 0; i < startingDay; i++) {
                calendarHtml += `<div class="border p-2 bg-gray-50"></div>`;
            }

            for (let day = 1; day <= daysInMonth; day++) {
                const currentDate = new Date(year, month, day);
                const reservationsForDay = reservations.filter(r => {
                    const start = new Date(r.start_date + 'T00:00:00');
                    const end = new Date(r.end_date + 'T00:00:00');
                    return currentDate >= start && currentDate <= end;
                });
                
                let eventsHtml = reservationsForDay.map(r => {
                     let cancelForm = '';
                     if(req.session.user.role !== 'user' || r.user_id === req.session.user.id) {
                         cancelForm = `<form class="inline" action="/reservations/cancel/${r.id}" method="POST"><button class="text-red-500 text-xs hover:underline ml-1">(Cancel)</button></form>`;
                     }
                     return `
                        <li class="bg-sky-100 p-1 rounded">
                            <p class="font-semibold">${r.item_name}</p>
                            <p>${r.user_name} ${cancelForm}</p>
                        </li>`;
                }).join('');

                calendarHtml += `<div class="border p-2 min-h-[120px]">
                    <div class="font-bold">${day}</div>
                    <ul class="text-xs space-y-1 mt-1">
                        ${eventsHtml}
                    </ul>
                </div>`;
            }

            const content = `
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div class="lg:col-span-2 card">
                        <div class="flex justify-between items-center mb-4">
                            <a href="/reservations?year=${prevYear}&month=${prevMonth}" class="btn btn-secondary">&lt; Prev</a>
                            <h2 class="text-xl font-bold">${monthName} ${year}</h2>
                            <a href="/reservations?year=${nextYear}&month=${nextMonth}" class="btn btn-secondary">Next &gt;</a>
                        </div>
                        <div class="grid grid-cols-7 gap-px bg-gray-200 border">
                            <div class="text-center font-bold p-2 bg-white">Sun</div>
                            <div class="text-center font-bold p-2 bg-white">Mon</div>
                            <div class="text-center font-bold p-2 bg-white">Tue</div>
                            <div class="text-center font-bold p-2 bg-white">Wed</div>
                            <div class="text-center font-bold p-2 bg-white">Thu</div>
                            <div class="text-center font-bold p-2 bg-white">Fri</div>
                            <div class="text-center font-bold p-2 bg-white">Sat</div>
                            ${calendarHtml}
                        </div>
                    </div>
                    <div class="card">
                        <h2 class="text-xl font-bold mb-4">Make a Reservation</h2>
                        <form action="/reservations" method="POST">
                            <div class="mb-4">
                                <label class="block">Item</label>
                                <select name="item_id" class="w-full p-2 border rounded" required>
                                    ${items.map(i => `<option value="${i.id}">${i.name}</option>`).join('')}
                                </select>
                            </div>
                            <div class="mb-4">
                                <label class="block">Start Date</label>
                                <input type="date" name="start_date" class="w-full p-2 border rounded" required>
                            </div>
                             <div class="mb-4">
                                <label class="block">End Date</label>
                                <input type="date" name="end_date" class="w-full p-2 border rounded" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-full">Reserve Item</button>
                        </form>
                    </div>
                </div>
            `;
            res.send(renderPage(req, 'Reservations', req.session.user, content));
        });
    });
});

app.post('/reservations', requireLogin, (req, res) => {
    const { item_id, start_date, end_date } = req.body;
    // Conflict check
    const sql = `SELECT id FROM reservations WHERE item_id = ? AND status = 'Active' AND (
        (start_date <= ? AND end_date >= ?) OR (start_date BETWEEN ? AND ?)
    )`;
    db.get(sql, [item_id, start_date, start_date, start_date, end_date], (err, existing) => {
        if (existing) {
            req.session.error = "This item is already reserved during the selected dates.";
            return res.redirect('/reservations');
        }
        db.run('INSERT INTO reservations (item_id, user_id, start_date, end_date) VALUES (?, ?, ?, ?)',
            [item_id, req.session.user.id, start_date, end_date], function(err) {
            if (err) {
                req.session.error = "Failed to create reservation.";
            } else {
                req.session.success = "Reservation created successfully.";
                logAction(req.session.user, 'Created Reservation', { id: item_id }, '', req.ip);
            }
            res.redirect('/reservations');
        });
    });
});

app.post('/reservations/cancel/:id', requireLogin, (req, res) => {
    const reservationId = req.params.id;
    db.get('SELECT user_id FROM reservations WHERE id = ?', [reservationId], (err, reservation) => {
        if (req.session.user.role === 'user' && req.session.user.id !== reservation.user_id) {
            req.session.error = "You can only cancel your own reservations.";
            return res.redirect('/reservations');
        }
        db.run("UPDATE reservations SET status = 'Cancelled' WHERE id = ?", [reservationId], function(err) {
            if (err) {
                req.session.error = "Failed to cancel reservation.";
            } else {
                req.session.success = "Reservation cancelled.";
                logAction(req.session.user, 'Cancelled Reservation', { id: reservationId }, '', req.ip);
            }
            res.redirect('/reservations');
        });
    });
});


app.get('/my-history', requireLogin, (req, res) => {
    const sql = `
        SELECT item_id, item_name, action, details, timestamp 
        FROM audit_log 
        WHERE user_id = ? AND action IN ('Checked Out Item', 'Checked In Item')
        ORDER BY timestamp DESC
    `;
    db.all(sql, [req.session.user.id], (err, logs) => {
        if (err) {
            req.session.error = "Could not retrieve your history.";
            return res.redirect('/dashboard');
        }
        const historyHtml = logs.length > 0 ? logs.map(log => `
            <tr class="border-b">
                <td class="py-2 px-4">${new Date(log.timestamp).toLocaleString()}</td>
                <td class="py-2 px-4"><a href="/inventory/view/${log.item_id}" class="text-sky-600 hover:underline">${log.item_name || 'N/A'}</a></td>
                <td class="py-2 px-4">${log.action}</td>
            </tr>
        `).join('') : '<tr><td colspan="3" class="text-center py-4">No history found.</td></tr>';

        const content = `
        <div class="card">
            <table class="w-full text-left">
                <thead><tr class="border-b-2">
                    <th class="py-2 px-4">Date</th>
                    <th class="py-2 px-4">Item Name</th>
                    <th class="py-2 px-4">Action</th>
                </tr></thead>
                <tbody>${historyHtml}</tbody>
            </table>
        </div>`;
        res.send(renderPage(req, 'My History', req.session.user, content));
    });
});

app.get('/requests/new', requireLogin, (req, res) => {
    const content = `
    <div class="card max-w-2xl mx-auto">
        <form action="/requests/new" method="POST">
            <div class="mb-4">
                <label class="block text-gray-700">Item Name*</label>
                <input type="text" name="item_name" class="w-full p-2 border rounded" required>
            </div>
            <div class="mb-4">
                <label class="block text-gray-700">Reason for Request*</label>
                <textarea name="reason" class="w-full p-2 border rounded" required></textarea>
            </div>
            <div class="mb-4">
                <label class="block text-gray-700">Link to Item (optional)</label>
                <input type="url" name="link" class="w-full p-2 border rounded" placeholder="https://example.com/item">
            </div>
            <button type="submit" class="btn btn-primary">Submit Request</button>
        </form>
    </div>`;
    res.send(renderPage(req, 'Request New Item', req.session.user, content));
});

app.post('/requests/new', requireLogin, (req, res) => {
    const { item_name, reason, link } = req.body;
    const sql = 'INSERT INTO purchase_requests (requested_by_id, item_name, reason, link) VALUES (?, ?, ?, ?)';
    db.run(sql, [req.session.user.id, item_name, reason, link], function(err) {
        if(err) {
            req.session.error = "Failed to submit request.";
            res.redirect('/requests/new');
        } else {
            logAction(req.session.user, 'Submitted Purchase Request', null, `Item: ${item_name}`, req.ip);
            req.session.success = "Your purchase request has been submitted for review.";
            res.redirect('/dashboard');
        }
    });
});

app.get('/reports', requireRole(['admin', 'manager']), (req, res) => {
    db.all("SELECT status, count(*) as count FROM items GROUP BY status", (err, itemStatusData) => {
        if (err) {
             return res.status(500).send(renderPage(req, 'Error', req.session.user, 'Could not load report data.'));
        }
        const availableCount = (itemStatusData.find(s => s.status === 'Available') || {count: 0}).count;
        const checkedOutCount = (itemStatusData.find(s => s.status === 'Checked Out') || {count: 0}).count;
        const maintenanceCount = (itemStatusData.find(s => s.status === 'Under Maintenance') || {count: 0}).count;

        const content = `
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div class="card">
                <h2 class="text-xl font-bold mb-4">Items by Status</h2>
                <canvas id="itemStatusChart"></canvas>
            </div>
        </div>
        <script>
            if (document.getElementById('itemStatusChart')) {
                const ctx = document.getElementById('itemStatusChart').getContext('2d');
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Available', 'Checked Out', 'Under Maintenance'],
                        datasets: [{
                            label: 'Item Status',
                            data: [
                                ${availableCount}, 
                                ${checkedOutCount}, 
                                ${maintenanceCount}
                            ],
                            backgroundColor: ['#22c55e', '#f59e0b', '#ef4444'],
                        }]
                    }
                });
            }
        </script>
        `;
        res.send(renderPage(req, 'Reports', req.session.user, content));
    });
});

app.get('/admin/requests', requireRole(['admin', 'manager']), (req, res) => {
    const sql = `
        SELECT pr.*, u.name as requester_name 
        FROM purchase_requests pr 
        JOIN users u ON pr.requested_by_id = u.id
        ORDER BY pr.request_date DESC
    `;
    db.all(sql, [], (err, requests) => {
        const requestsHtml = requests.length > 0 ? requests.map(r => `
            <tr class="border-b ${r.status === 'Pending' ? 'bg-yellow-50' : ''}">
                <td class="py-2 px-4">${r.item_name} ${r.link ? `<a href="${r.link}" target="_blank" class="text-sky-500">(link)</a>` : ''}</td>
                <td class="py-2 px-4">${r.requester_name}</td>
                <td class="py-2 px-4">${r.reason}</td>
                <td class="py-2 px-4">${r.status}</td>
                <td class="py-2 px-4">
                    ${r.status === 'Pending' ? `
                    <div class="flex gap-2">
                        <form action="/admin/requests/approve/${r.id}" method="POST">
                            <button type="submit" class="btn btn-primary text-sm">Approve</button>
                        </form>
                         <form action="/admin/requests/deny/${r.id}" method="POST">
                            <button type="submit" class="btn btn-danger text-sm">Deny</button>
                        </form>
                    </div>` : ''}
                </td>
            </tr>
        `).join('') : `<tr><td colspan="5" class="text-center py-4">No purchase requests found.</td></tr>`;

        const content = `
        <div class="card">
            <table class="w-full text-left">
                <thead><tr class="border-b-2">
                    <th class="py-2 px-4">Item</th>
                    <th class="py-2 px-4">Requester</th>
                    <th class="py-2 px-4">Reason</th>
                    <th class="py-2 px-4">Status</th>
                    <th class="py-2 px-4">Actions</th>
                </tr></thead>
                <tbody>${requestsHtml}</tbody>
            </table>
        </div>`;
        res.send(renderPage(req, 'Purchase Requests', req.session.user, content));
    });
});

app.post('/admin/requests/:action/:id', requireRole(['admin', 'manager']), (req, res) => {
    const { action, id } = req.params;
    const status = action === 'approve' ? 'Approved' : 'Denied';

    db.get('SELECT * FROM purchase_requests WHERE id = ?', [id], (err, request) => {
        if(err || !request) {
            req.session.error = "Request not found.";
            return res.redirect('/admin/requests');
        }

        db.run('UPDATE purchase_requests SET status = ?, reviewed_by_id = ?, review_date = CURRENT_TIMESTAMP WHERE id = ?', 
            [status, req.session.user.id, id], (err) => {
            if(err) {
                req.session.error = "Failed to update request.";
                return res.redirect('/admin/requests');
            }
            logAction(req.session.user, `Purchase Request ${status}`, null, `Request for: ${request.item_name}`, req.ip);

            if (status === 'Approved') {
                const itemSql = `INSERT INTO items (name, category, manufacturer) VALUES (?, ?, ?)`;
                db.run(itemSql, [request.item_name, 'Requested', 'N/A'], function(err) {
                     if(err) {
                        req.session.error = "Request approved, but failed to auto-add item.";
                     } else {
                        req.session.success = `Request approved and item "${request.item_name}" has been added to inventory.`;
                     }
                     res.redirect('/admin/requests');
                });
            } else {
                 req.session.success = "Request has been denied.";
                 res.redirect('/admin/requests');
            }
        });
    });
});


app.get('/admin/password-resets', requireRole(['admin']), (req, res) => {
    const sql = `
        SELECT pr.id, u.name, u.student_id, pr.request_date
        FROM password_resets pr
        JOIN users u ON pr.user_id = u.id
        WHERE pr.status = 'Pending'
        ORDER BY pr.request_date ASC
    `;
    db.all(sql, [], (err, resets) => {
        const resetsHtml = resets.length > 0 ? resets.map(r => `
            <tr class="border-b">
                <td class="py-2 px-4">${r.name} (${r.student_id})</td>
                <td class="py-2 px-4">${new Date(r.request_date).toLocaleString()}</td>
                <td class="py-2 px-4">
                    <form action="/admin/password-resets/${r.id}" method="POST" class="flex items-center gap-2">
                        <input type="text" name="new_password" placeholder="New Temporary Password" class="p-1 border rounded" required>
                        <button type="submit" class="btn btn-primary text-sm">Reset</button>
                    </form>
                </td>
            </tr>
        `).join('') : `<tr><td colspan="3" class="text-center py-4">No pending password resets.</td></tr>`;

        const content = `
        <div class="card">
            <table class="w-full text-left">
                <thead><tr class="border-b-2">
                    <th class="py-2 px-4">User</th>
                    <th class="py-2 px-4">Date Requested</th>
                    <th class="py-2 px-4">Action</th>
                </tr></thead>
                <tbody>${resetsHtml}</tbody>
            </table>
        </div>`;
        res.send(renderPage(req, 'Password Resets', req.session.user, content));
    });
});

app.post('/admin/password-resets/:id', requireRole(['admin']), (req, res) => {
    const { new_password } = req.body;
    const resetId = req.params.id;
    db.get('SELECT user_id FROM password_resets WHERE id = ?', [resetId], (err, reset) => {
        if(err || !reset) {
            req.session.error = "Reset request not found.";
            return res.redirect('/admin/password-resets');
        }
        bcrypt.hash(new_password, SALT_ROUNDS, (err, hash) => {
            db.run('UPDATE users SET password = ? WHERE id = ?', [hash, reset.user_id], (err) => {
                db.run('UPDATE password_resets SET status = ? WHERE id = ?', ['Completed', resetId]);
                logAction(req.session.user, 'Reset User Password', null, `User ID: ${reset.user_id}`, req.ip);
                req.session.success = "Password has been reset. Please provide the new password to the user.";
                res.redirect('/admin/password-resets');
            });
        });
    });
});

app.get('/locations', requireRole(['admin', 'manager']), (req, res) => {
    db.all("SELECT * FROM locations ORDER BY name", (err, locations) => {
        const locationsHtml = locations.map(l => `<li class="p-2 border-b">${l.name}</li>`).join('');
        const content = `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="card">
                <h2 class="text-xl font-bold mb-4">Existing Locations</h2>
                <ul>${locationsHtml}</ul>
            </div>
            <div class="card">
                 <h2 class="text-xl font-bold mb-4">Add New Location</h2>
                 <form action="/locations" method="POST">
                    <div class="mb-4">
                        <label class="block">Location Name (e.g., Cabinet A, Shelf B-2)</label>
                        <input type="text" name="name" class="w-full p-2 border rounded" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Add Location</button>
                 </form>
            </div>
        </div>`;
        res.send(renderPage(req, 'Locations/Cabinets', req.session.user, content));
    });
});

app.post('/locations', requireRole(['admin', 'manager']), (req, res) => {
    const { name } = req.body;
    db.run('INSERT INTO locations (name) VALUES (?)', [name], function(err) {
        if(err) {
            req.session.error = "Failed to add location. It may already exist.";
        } else {
            req.session.success = "Location added successfully.";
            logAction(req.session.user, 'Created Location', null, `Name: ${name}`, req.ip);
        }
        res.redirect('/locations');
    });
});

app.get('/audit-log', requireRole(['admin']), (req, res) => {
    db.all("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100", (err, logs) => {
        const logsHtml = logs.map(l => `
            <tr class="border-b">
                <td class="py-2 px-4">${new Date(l.timestamp).toLocaleString()}</td>
                <td class="py-2 px-4">${l.user_name}</td>
                <td class="py-2 px-4">${l.action}</td>
                <td class="py-2 px-4">${l.item_name || 'N/A'}</td>
                <td class="py-2 px-4">${l.details || ''}</td>
                 <td class="py-2 px-4">${l.ip_address || 'N/A'}</td>
            </tr>
        `).join('');
        const content = `<div class="card">
            <table class="w-full text-left">
                <thead><tr class="border-b-2">
                    <th class="py-2 px-4">Timestamp</th>
                    <th class="py-2 px-4">User</th>
                    <th class="py-2 px-4">Action</th>
                    <th class="py-2 px-4">Item</th>
                    <th class="py-2 px-4">Details</th>
                    <th class="py-2 px-4">IP Address</th>
                </tr></thead>
                <tbody>${logsHtml}</tbody>
            </table>
        </div>`;
        res.send(renderPage(req, 'Audit Log', req.session.user, content));
    });
});

app.get('/data', requireRole(['admin']), (req, res) => {
    const content = `<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="card">
            <h2 class="text-xl font-bold mb-4">Import Inventory</h2>
            <p class="mb-4">Upload a CSV file with columns: name, category, model_number, serial_number, manufacturer, condition, quantity.</p>
            <form action="/data/import" method="POST" enctype="multipart/form-data">
                <input type="file" name="csvFile" accept=".csv" class="w-full p-2 border rounded mb-4" required>
                <button type="submit" class="btn btn-primary">Import CSV</button>
            </form>
        </div>
        <div class="card">
            <h2 class="text-xl font-bold mb-4">Export Data</h2>
            <p class="mb-4">Download a complete CSV file of the current inventory or the full audit log.</p>
            <div class="flex gap-4">
                <a href="/data/export/items" class="btn btn-secondary">Export Inventory</a>
                <a href="/data/export/audit" class="btn btn-secondary">Export Audit Log</a>
            </div>
        </div>
    </div>`;
    res.send(renderPage(req, 'Data Management', req.session.user, content));
});

app.post('/data/import', requireRole(['admin']), upload.single('csvFile'), (req, res) => {
    if (!req.file) {
        req.session.error = "No CSV file uploaded.";
        return res.redirect('/data');
    }

    const items = [];
    fs.createReadStream(req.file.path)
        .pipe(csv.parse({ headers: true }))
        .on('error', error => {
            req.session.error = `Error parsing CSV: ${error.message}`;
            res.redirect('/data');
        })
        .on('data', row => items.push(row))
        .on('end', rowCount => {
            const sql = `INSERT INTO items (name, category, model_number, serial_number, manufacturer, condition, quantity) VALUES (?, ?, ?, ?, ?, ?, ?)`;
            let successCount = 0;
            let errorCount = 0;
            
            db.serialize(() => {
                const stmt = db.prepare(sql);
                items.forEach(item => {
                    stmt.run([item.name, item.category, item.model_number, item.serial_number, item.manufacturer, item.condition, item.quantity], (err) => {
                        if (err) errorCount++;
                        else successCount++;
                    });
                });
                stmt.finalize((err) => {
                    logAction(req.session.user, 'Imported Data', null, `Imported ${successCount} items from CSV. ${errorCount} errors.`, req.ip);
                    req.session.success = `Successfully imported ${successCount} items. Failed to import ${errorCount} items (likely duplicate serial numbers).`;
                    fs.unlinkSync(req.file.path); // Clean up uploaded file
                    res.redirect('/inventory');
                });
            });
        });
});

app.get('/data/export/:type', requireRole(['admin']), (req, res) => {
    const { type } = req.params;
    const table = type === 'items' ? 'items' : 'audit_log';
    const filename = `${type}_export_${Date.now()}.csv`;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=${filename}`);

    const csvStream = csv.format({ headers: true });
    csvStream.pipe(res);

    db.each(`SELECT * FROM ${table}`, (err, row) => {
        if(err) { console.error(err); }
        else { csvStream.write(row); }
    }, () => {
        csvStream.end();
        logAction(req.session.user, 'Exported Data', null, `Exported ${type} to CSV.`, req.ip);
    });
});


// 404 Handler - Must be the last route
app.use((req, res, next) => {
    const content = `
        <div class="text-center">
            <h1 class="text-6xl font-bold text-sky-600">404</h1>
            <p class="text-xl text-gray-700 mt-4">Oops! The page you're looking for could not be found.</p>
            <a href="/dashboard" class="mt-6 inline-block btn btn-primary">Go to Dashboard</a>
        </div>
    `;
    res.status(404).send(renderPage(req, 'Page Not Found', req.session.user, content));
});


// 8. START SERVER
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
    console.log(`For Miami Beach Senior High Robotics Team`);
});


