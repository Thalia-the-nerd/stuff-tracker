/*
 * =================================================================
 * Miami Beach Senior High Robotics Team - Inventory Tracker
 * =================================================================
 * Version: 3.0.7 (Kit Logic Fix)
 * Author: Thalia (with fixes by Gemini)
 * Description: A complete, single-file Node.js application to manage
 * team inventory with advanced admin controls and a refreshed UI.
 *
 * Change Log (v3.0.7):
 * - FIXED: A critical logic bug where checking in a multi-quantity item would incorrectly keep its status as "Checked Out".
 * - REMOVED: Dark mode was reverted to the default light theme.
 *
 * Change Log (v3.0.5):
 * - ADDED: Item "Kit" functionality. Items can be designated as kits and require other items as components.
 * - ADDED: Checkout logic now validates that all kit components are available. Checking out a kit checks out all its components.
 * - ADDED: UI for managing kit components on the item edit page.
 * - ADDED: Sorting functionality to the main inventory table (sort by ID, name, category, status).
 * - IMPROVED: Quantity tracking. Items with multiple quantities now show how many are checked out (e.g., "1/3 Checked Out").
 * - SECURITY: Session secret is now loaded from an environment variable (`process.env.SESSION_SECRET`).
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
const crypto = require('crypto'); // For session secret

const app = express();
const PORT = process.env.PORT || 4899;
const SALT_ROUNDS = 10;
const UPLOAD_PATH = 'uploads';
const IMAGE_PATH = path.join(UPLOAD_PATH, 'images');
const CSV_PATH = path.join(UPLOAD_PATH, 'csv');
const RESERVATION_LIMIT_DAYS = 14;


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
            quantity_checked_out INTEGER DEFAULT 0,
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
            extension_status TEXT DEFAULT 'None' CHECK(extension_status IN ('None', 'Pending', 'Approved', 'Denied')),
            requested_end_date DATE,
            extension_reason TEXT,
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
        
        // --- Schema Integrity Checks (Hotfixes for existing databases) ---
        function checkAndAddColumn(table, column, definition) {
            db.all(`PRAGMA table_info(${table})`, (err, columns) => {
                if (err) return;
                const hasColumn = columns.some(col => col.name === column);
                if (!hasColumn) {
                    console.log(`Updating ${table} schema: Adding ${column} column...`);
                    db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`, (alterErr) => {
                        if (alterErr) console.error(`Failed to update ${table} schema:`, alterErr);
                        else console.log(`Schema for ${table} updated successfully.`);
                    });
                }
            });
        }
        checkAndAddColumn('audit_log', 'ip_address', 'TEXT');
        checkAndAddColumn('reservations', 'extension_status', "TEXT DEFAULT 'None' CHECK(extension_status IN ('None', 'Pending', 'Approved', 'Denied'))");
        checkAndAddColumn('reservations', 'requested_end_date', 'DATE');
        checkAndAddColumn('reservations', 'extension_reason', 'TEXT');
        checkAndAddColumn('items', 'is_kit', 'BOOLEAN DEFAULT 0');
        checkAndAddColumn('items', 'quantity_checked_out', 'INTEGER DEFAULT 0');


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
    const itemName = item ? item.name : null;

    db.run('INSERT INTO audit_log (user_id, user_name, action, item_id, item_name, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [userId, userName, action, itemId, itemName, details, ip]);
}


// 5. MIDDLEWARE
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// SECURITY: Use environment variables for session secret in production.
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (process.env.SESSION_SECRET === undefined) {
    console.warn('WARNING: SESSION_SECRET is not set. Using a temporary secret. Please set this in your environment for production.');
}

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    // NOTE: For production behind HTTPS, uncomment the following line
    // cookie: { secure: true } 
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
    
    const navLinks = [
        { name: 'Dashboard', href: '/dashboard', roles: ['admin', 'manager', 'user'] },
        { name: 'Inventory', href: '/inventory', roles: ['admin', 'manager', 'user'] },
        { name: 'Scan QR Code', href: '/scan', roles: ['admin', 'manager', 'user'] },
        { name: 'Reservations Calendar', href: '/reservations', roles: ['admin', 'manager', 'user'] },
        { name: 'My Reservations', href: '/my-reservations', roles: ['admin', 'manager', 'user'] },
        { name: 'Request Item', href: '/requests/new', roles: ['admin', 'manager', 'user'] },
    ];
    const adminLinks = [
        { name: 'Reports', href: '/reports', roles: ['admin', 'manager'] },
        { name: 'All Reservations', href: '/admin/all-reservations', roles: ['admin', 'manager'] },
        { name: 'Purchase Requests', href: '/admin/requests', roles: ['admin', 'manager'] },
        { name: 'Extension Requests', href: '/admin/extensions', roles: ['admin', 'manager'] },
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
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
            <script src="https://cdn.tailwindcss.com"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: 'Inter', sans-serif; }
                .sidebar-link { transition: all 0.2s; }
                .sidebar-link:hover, .sidebar-link.active { background-color: #0369a1; color: white; } /* sky-700 */
                .btn { @apply font-bold py-2 px-4 rounded-lg transition-colors shadow-sm; }
                .btn-primary { @apply bg-sky-600 text-white hover:bg-sky-700; }
                .btn-secondary { @apply bg-gray-200 text-gray-800 hover:bg-gray-300; }
                .btn-danger { @apply bg-red-600 text-white hover:bg-red-700; }
                .btn-warning { @apply bg-amber-500 text-white hover:bg-amber-600; }
                .card { @apply bg-white rounded-xl shadow-md p-4 md:p-6; }
            </style>
        </head>
        <body class="h-full">
            <div class="min-h-full">
                ${user ? `
                <!-- Mobile header -->
                <header class="lg:hidden bg-gray-800 text-white p-4 flex justify-between items-center sticky top-0 z-20 shadow-lg">
                    <h1 class="text-lg font-bold">${title}</h1>
                    <button id="menu-btn" class="p-2">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                        </svg>
                    </button>
                </header>
                
                <!-- Sidebar -->
                <aside id="sidebar" class="w-64 bg-gray-800 text-gray-200 flex flex-col p-4 space-y-1 fixed h-full overflow-y-auto z-30 transform -translate-x-full lg:translate-x-0 transition-transform duration-300 ease-in-out">
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
                
                <!-- Main Content -->
                <div class="flex-1 ${user ? 'lg:ml-64' : ''}">
                    <main class="p-4 md:p-10">
                        <h1 class="hidden lg:block text-3xl font-bold text-gray-800 mb-6">${title}</h1>
                        ${error ? `<div class="mb-4 p-4 bg-red-100 text-red-800 border border-red-300 rounded-lg shadow">${error}</div>` : ''}
                        ${success ? `<div class="mb-4 p-4 bg-green-100 text-green-800 border border-green-300 rounded-lg shadow">${success}</div>` : ''}
                        ${content}
                    </main>
                </div>
            </div>
            ${user ? `
            <div id="sidebar-overlay" class="fixed inset-0 bg-black bg-opacity-50 z-20 hidden lg:hidden"></div>
            <script>
                const menuBtn = document.getElementById('menu-btn');
                const sidebar = document.getElementById('sidebar');
                const overlay = document.getElementById('sidebar-overlay');

                if (menuBtn && sidebar && overlay) {
                    menuBtn.addEventListener('click', () => {
                        sidebar.classList.toggle('-translate-x-full');
                        overlay.classList.toggle('hidden');
                    });
                    overlay.addEventListener('click', () => {
                        sidebar.classList.add('-translate-x-full');
                        overlay.classList.add('hidden');
                    });
                }
            </script>
            ` : ''}
        </body>
        </html>
    `;
};

// 7. APPLICATION ROUTES

// --- Root and Dashboard ---
app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/dashboard', requireLogin, (req, res) => {
    const sql = `
        SELECT
            (SELECT COUNT(*) FROM items) as total_items,
            (SELECT SUM(quantity_checked_out) FROM items) as checked_out_items,
            (SELECT COUNT(*) FROM items WHERE status = 'Under Maintenance') as maintenance_items,
            (SELECT COUNT(*) FROM purchase_requests WHERE status = 'Pending') as pending_requests,
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT COUNT(*) FROM reservations WHERE extension_status = 'Pending') as pending_extensions,
            (SELECT COUNT(*) FROM password_resets WHERE status = 'Pending') as pending_resets
    `;
    db.get(sql, (err, stats) => {
        if(err) {
            return res.status(500).send(renderPage(req, 'Error', req.session.user, 'Could not load dashboard data.'));
        }
        db.all(`SELECT al.*, i.name as item_name FROM audit_log al LEFT JOIN items i ON al.item_id = i.id ORDER BY timestamp DESC LIMIT 5`, (err, recent_activity) => {
            let admin_cards = '';
            if (req.session.user.role !== 'user') {
                 admin_cards = `
                    <div class="card text-center bg-cyan-50">
                        <a href="/admin/extensions" class="block">
                            <h2 class="text-4xl font-bold text-cyan-600">${stats.pending_extensions || 0}</h2>
                            <p class="text-gray-500">Pending Extensions</p>
                        </a>
                    </div>
                `;
            }
            if (req.session.user.role === 'admin') {
                admin_cards += `
                    <div class="card text-center bg-orange-50">
                        <a href="/admin/password-resets" class="block">
                            <h2 class="text-4xl font-bold text-orange-600">${stats.pending_resets || 0}</h2>
                            <p class="text-gray-500">Pending Password Resets</p>
                        </a>
                    </div>
                    <div class="card text-center">
                        <a href="/users" class="block">
                            <h2 class="text-4xl font-bold text-gray-600">${stats.total_users || 0}</h2>
                            <p class="text-gray-500">Total Users</p>
                        </a>
                    </div>
                `;
            }
            const content = `
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <div class="card text-center">
                        <a href="/inventory" class="block">
                            <h2 class="text-4xl font-bold text-sky-600">${stats.total_items || 0}</h2>
                            <p class="text-gray-500">Total Unique Items</p>
                        </a>
                    </div>
                    <div class="card text-center">
                        <h2 class="text-4xl font-bold text-yellow-600">${stats.checked_out_items || 0}</h2>
                        <p class="text-gray-500">Individual Items Checked Out</p>
                    </div>
                     <div class="card text-center">
                        <h2 class="text-4xl font-bold text-red-600">${stats.maintenance_items || 0}</h2>
                        <p class="text-gray-500">Items in Maintenance</p>
                    </div>
                    <div class="card text-center">
                         <a href="/admin/requests" class="block">
                            <h2 class="text-4xl font-bold text-blue-600">${stats.pending_requests || 0}</h2>
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

        if (user.status === 'banned') {
            req.session.error = "This account has been banned.";
            return res.redirect('/login');
        }
        if (user.status === 'timed_out') {
            if (new Date(user.timeout_until) > new Date()) {
                req.session.error = `This account is in a timeout until ${new Date(user.timeout_until).toLocaleString()}.`;
                return res.redirect('/login');
            } else {
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
                    req.session.user = newUser;
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
            res.send(`<body style="background:white; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;"><img src="${dataUrl}" alt="QR Code"></body>`);
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


// --- Inventory Management ---

app.get('/inventory', requireLogin, (req,res) => {
    const { sortBy, order } = req.query;
    const validSorts = ['id', 'name', 'category', 'location_name', 'status'];
    const validOrders = ['asc', 'desc'];

    let orderBy = 'i.name';
    let orderDirection = 'ASC';

    if (validSorts.includes(sortBy) && validOrders.includes(order)) {
        orderBy = `i.${sortBy}`;
        if (sortBy === 'location_name') orderBy = `l.name`;
        orderDirection = order.toUpperCase();
    }
    
    const sql = `SELECT i.*, l.name as location_name FROM items i LEFT JOIN locations l ON i.location_id = l.id ORDER BY ${orderBy} ${orderDirection}`;

    db.all(sql, (err, items) => {
        const sortLink = (col, name) => {
            const newOrder = sortBy === col && order === 'asc' ? 'desc' : 'asc';
            const icon = sortBy === col ? (order === 'asc' ? '&#9650;' : '&#9660;') : '';
            return `<a href="/inventory?sortBy=${col}&order=${newOrder}" class="hover:underline flex items-center gap-1">${name} ${icon}</a>`;
        }

        const renderStatusBadge = (item) => {
            let statusText = '';
            let statusColor = '';
            if (item.status === 'Under Maintenance') {
                statusText = 'Maintenance';
                statusColor = 'bg-red-100 text-red-800';
            } else if (item.quantity_checked_out >= item.quantity) {
                statusText = 'Checked Out';
                statusColor = 'bg-yellow-100 text-yellow-800';
            } else if (item.quantity_checked_out > 0) {
                statusText = `${item.quantity_checked_out} / ${item.quantity} Checked Out`;
                statusColor = 'bg-blue-100 text-blue-800';
            } else {
                statusText = 'Available';
                statusColor = 'bg-green-100 text-green-800';
            }
            return `<span class="font-semibold px-2 py-1 rounded-full text-xs ${statusColor}">${statusText}</span>`;
        };

        const itemsHtml = items.map(item => `
            <tr class="border-b hover:bg-gray-50">
                <td class="py-2 px-4">${item.id}</td>
                <td class="py-2 px-4 font-semibold text-sky-700">${item.name} ${item.is_kit ? '<span class="text-xs bg-gray-200 px-1 py-0.5 rounded">Kit</span>' : ''}</td>
                <td class="py-2 px-4 hidden sm:table-cell">${item.category || 'N/A'}</td>
                <td class="py-2 px-4 hidden lg:table-cell">${item.location_name || 'N/A'}</td>
                <td class="py-2 px-4">${renderStatusBadge(item)}</td>
                <td class="py-2 px-4"><a href="/inventory/view/${item.id}" class="text-sky-600 hover:underline">Details</a></td>
            </tr>
        `).join('');

        const itemsCardsHtml = items.map(item => `
            <div class="card mb-4">
                <div class="font-bold text-lg text-sky-700">${item.name} ${item.is_kit ? '<span class="text-xs bg-gray-200 px-1 py-0.5 rounded">Kit</span>' : ''}</div>
                <div class="text-sm text-gray-500 mb-2">ID: ${item.id}</div>
                <div class="space-y-1 text-sm">
                    <p><strong>Category:</strong> ${item.category || 'N/A'}</p>
                    <p><strong>Location:</strong> ${item.location_name || 'N/A'}</p>
                    <div class="flex items-center"><strong>Status:</strong>&nbsp; ${renderStatusBadge(item)}</div>
                </div>
                <div class="mt-4"><a href="/inventory/view/${item.id}" class="btn btn-primary w-full text-center">View Details</a></div>
            </div>
        `).join('');

        const content = `
        <div class="flex justify-between items-center mb-4">
            <div></div>
            <a href="/inventory/add" class="btn btn-primary">Add New Item</a>
        </div>
        <div class="card overflow-x-auto hidden md:block">
            <table class="w-full text-left">
                <thead><tr class="border-b-2">
                    <th class="py-2 px-4">${sortLink('id', 'ID')}</th>
                    <th class="py-2 px-4">${sortLink('name', 'Name')}</th>
                    <th class="py-2 px-4 hidden sm:table-cell">${sortLink('category', 'Category')}</th>
                    <th class="py-2 px-4 hidden lg:table-cell">${sortLink('location_name', 'Location')}</th>
                    <th class="py-2 px-4">${sortLink('status', 'Status')}</th>
                    <th class="py-2 px-4">Actions</th>
                </tr></thead>
                <tbody>${itemsHtml}</tbody>
            </table>
        </div>
        <div class="md:hidden">${itemsCardsHtml}</div>
        `;
        res.send(renderPage(req, 'Inventory', req.session.user, content));
    });
});

app.get('/inventory/add', requireRole(['admin', 'manager']), (req, res) => {
    db.all('SELECT * FROM locations', (err, locations) => {
    db.all('SELECT DISTINCT manufacturer FROM items WHERE manufacturer IS NOT NULL AND manufacturer != "" ORDER BY manufacturer', (err, manufacturers) => {
    db.all('SELECT DISTINCT condition FROM items WHERE condition IS NOT NULL AND condition != "" ORDER BY condition', (err, conditions) => {

        const locationsOptions = locations.map(l => `<option value="${l.id}">${l.name}</option>`).join('');
        const manufacturersDatalist = manufacturers.map(m => `<option value="${m.manufacturer}"></option>`).join('');
        const conditionsDatalist = conditions.map(c => `<option value="${c.condition}"></option>`).join('');

        const content = `
            <div class="card max-w-4xl mx-auto">
                <form action="/inventory/add" method="POST" enctype="multipart/form-data">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div><label class="block">Name*</label><input type="text" name="name" class="w-full p-2 border rounded" required></div>
                        <div><label class="block">Category</label><input type="text" name="category" class="w-full p-2 border rounded"></div>
                        <div><label class="block">Model Number</label><input type="text" name="model_number" class="w-full p-2 border rounded"></div>
                        <div><label class="block">Serial Number (optional)</label><input type="text" name="serial_number" class="w-full p-2 border rounded"></div>
                        
                        <div>
                            <label class="block">Manufacturer/Supplier</label>
                            <input type="text" name="manufacturer" list="manufacturer-list" class="w-full p-2 border rounded">
                            <datalist id="manufacturer-list">${manufacturersDatalist}</datalist>
                        </div>
                        <div>
                            <label class="block">Condition</label>
                            <input type="text" name="condition" list="condition-list" class="w-full p-2 border rounded">
                            <datalist id="condition-list">${conditionsDatalist}</datalist>
                        </div>

                        <div><label class="block">Location</label><select name="location_id" class="w-full p-2 border rounded">${locationsOptions}</select></div>
                        <div><label class="block">Quantity</label><input type="number" name="quantity" value="1" min="1" class="w-full p-2 border rounded"></div>
                        <div class="md:col-span-2"><label class="block">Specifications</label><textarea name="specifications" class="w-full p-2 border rounded"></textarea></div>
                        <div class="md:col-span-2"><label class="block">Comment</label><textarea name="comment" class="w-full p-2 border rounded"></textarea></div>
                        <div><label class="block">Image</label><input type="file" name="itemImage" class="w-full p-2 border rounded"></div>
                        <div class="flex items-center gap-2">
                           <input type="checkbox" name="is_kit" id="is_kit" value="1" class="h-4 w-4 rounded border-gray-300 text-sky-600 focus:ring-sky-500">
                           <label for="is_kit">This item is a kit (contains other items)</label>
                        </div>
                    </div>
                    <div class="mt-6"><button type="submit" class="btn btn-primary">Add Item</button></div>
                </form>
            </div>
        `;
        res.send(renderPage(req, 'Add New Item', req.session.user, content));
    });
    });
    });
});

app.post('/inventory/add', requireRole(['admin', 'manager']), upload.single('itemImage'), (req, res) => {
    const { name, quantity, model_number, serial_number, manufacturer, category, condition, specifications, location_id, comment } = req.body;
    const is_kit = req.body.is_kit ? 1 : 0;
    
    const finalSerialNumber = serial_number && serial_number.trim() !== '' ? serial_number.trim() : `MBSH-${Date.now()}`;
    
    const imageUrl = req.file ? `/uploads/images/${req.file.filename}` : null;
    
    const sql = `INSERT INTO items (name, quantity, model_number, serial_number, manufacturer, category, condition, specifications, location_id, comment, image_url, is_kit, last_activity_date)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`;
    
    db.run(sql, [name, quantity, model_number, finalSerialNumber, manufacturer, category, condition, specifications, location_id, comment, imageUrl, is_kit], function(err) {
        if (err) {
            req.session.error = `Failed to add item. Serial number might already exist. Error: ${err.message}`;
            res.redirect('/inventory/add');
        } else {
            const newItemId = this.lastID;
            const newItem = { id: newItemId, name: name };
            logAction(req.session.user, 'Created Item', newItem, '', req.ip);
            req.session.success = "Item added successfully.";
            if (is_kit) {
                res.redirect(`/inventory/edit/${newItemId}`);
            } else {
                res.redirect('/inventory');
            }
        }
    });
});

app.get('/inventory/view/:id', requireLogin, async (req, res) => {
    const itemId = req.params.id;
    db.get(`SELECT i.*, l.name as location_name FROM items i LEFT JOIN locations l ON i.location_id = l.id WHERE i.id = ?`, [itemId], async (err, item) => {
        if(err || !item) {
            req.session.error = "Item not found.";
            return res.redirect('/inventory');
        }
        
        db.all('SELECT ml.*, u.name as reporter_name FROM maintenance_log ml LEFT JOIN users u ON ml.user_id = u.id WHERE item_id = ? ORDER BY report_date DESC', [itemId], (err, maintenance_logs) => {
        db.all('SELECT i.id, i.name FROM items i JOIN kits k ON i.id = k.item_id WHERE k.kit_id = ?', [itemId], async (err, kit_components) => {

            const qrCodeUrl = await QRCode.toDataURL(`${req.protocol}://${req.get('host')}/quick-action/${itemId}`);
            
            const openMaintenanceLog = maintenance_logs.find(log => !log.resolved_date);

            let adminActions = '';
            if(req.session.user.role !== 'user') {
                adminActions = `<div class="flex gap-2"><a href="/inventory/edit/${item.id}" class="btn btn-secondary">Edit</a>
                <form action="/inventory/delete/${item.id}" method="POST" onsubmit="return confirm('Are you sure you want to permanently delete this item?');">
                    <button type="submit" class="btn btn-danger">Delete</button>
                </form></div>`;
            }
            
            let actionBox = '';
            if (item.status !== 'Under Maintenance') {
                 if (item.quantity_checked_out < item.quantity) {
                    actionBox += `<form action="/inventory/checkout/${item.id}" method="POST"><button type="submit" class="btn btn-primary w-full mb-2">Check Out</button></form>`;
                }
                if (item.quantity_checked_out > 0) {
                     actionBox += `<form action="/inventory/checkin/${item.id}" method="POST"><button type="submit" class="btn btn-secondary w-full">Check In</button></form>`;
                }
            } else if (req.session.user.role !== 'user' && openMaintenanceLog) {
                actionBox = `
                    <div class="bg-yellow-50 p-4 rounded-lg">
                        <h4 class="font-bold text-yellow-800">Resolve Maintenance Issue</h4>
                        <p class="text-sm text-gray-600 mb-2"><strong>Issue:</strong> ${openMaintenanceLog.description}</p>
                        <form action="/maintenance/resolve/${openMaintenanceLog.id}" method="POST">
                            <textarea name="resolution_notes" class="w-full p-2 border rounded" placeholder="Enter resolution notes..." required></textarea>
                            <button type="submit" class="btn btn-primary w-full mt-2">Mark as Resolved</button>
                        </form>
                    </div>
                `;
            }

            if (actionBox === '') {
                actionBox = `<p class="text-center text-gray-500">No actions available.</p>`;
            }
            
            let maintenanceBox = `<div class="mt-4">
                <h4 class="font-bold">Report an Issue</h4>
                <form action="/maintenance/report/${item.id}" method="POST">
                    <textarea name="description" class="w-full p-2 border rounded" placeholder="Describe the issue..." required></textarea>
                    <button type="submit" class="btn btn-warning w-full mt-2">Submit Report</button>
                </form>
            </div>`;

            const maintenanceHistory = maintenance_logs.length > 0 ? `
                <div class="mt-4 pt-4 border-t">
                    <h3 class="font-bold">Maintenance History</h3>
                    <ul class="divide-y">${maintenance_logs.map(log => `
                        <li class="py-2">
                            <p><strong>${log.description}</strong> - Reported by ${log.reporter_name || 'Deleted User'}</p>
                            <p class="text-sm text-gray-500">${new Date(log.report_date).toLocaleString()}</p>
                            ${log.resolved_date 
                                ? `<p class="text-sm text-green-700 bg-green-100 p-2 rounded-md mt-1"><strong>Resolved:</strong> ${log.resolution_notes || 'Issue marked as resolved.'}</p>` 
                                : '<p class="text-sm text-red-700"><strong>Status:</strong> Unresolved</p>'}
                        </li>
                    `).join('')}</ul>
                </div>` : '';
            
            let kitDetailsHtml = '';
            if (item.is_kit) {
                kitDetailsHtml = `
                <div class="mt-4 pt-4 border-t">
                    <h3 class="font-bold">Kit Components</h3>
                    ${kit_components.length > 0 ? `
                    <ul class="list-disc list-inside mt-2">
                        ${kit_components.map(c => `<li><a href="/inventory/view/${c.id}" class="text-sky-600 hover:underline">${c.name}</a></li>`).join('')}
                    </ul>
                    ` : '<p class="text-gray-600 mt-2">No components assigned. You can add them in the edit screen.</p>'}
                </div>
                `;
            }
            
            const renderStatusBadge = (item) => {
                let statusText = '';
                let statusColor = '';
                if (item.status === 'Under Maintenance') {
                    statusText = 'Maintenance';
                    statusColor = 'bg-red-100 text-red-800';
                } else if (item.quantity_checked_out >= item.quantity) {
                    statusText = 'Checked Out';
                    statusColor = 'bg-yellow-100 text-yellow-800';
                } else if (item.quantity_checked_out > 0) {
                    statusText = `${item.quantity_checked_out} / ${item.quantity} Checked Out`;
                    statusColor = 'bg-blue-100 text-blue-800';
                } else {
                    statusText = 'Available';
                    statusColor = 'bg-green-100 text-green-800';
                }
                return `<span class="font-semibold px-2 py-1 rounded-full text-xs ${statusColor}">${statusText}</span>`;
            };


            const content = `
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div class="lg:col-span-2">
                        <div class="card">
                            <div class="flex flex-col sm:flex-row justify-between sm:items-start gap-4">
                                 <h2 class="text-2xl font-bold">${item.name}</h2>
                                 ${adminActions}
                            </div>
                            <p class="text-gray-500 mb-4">Category: ${item.category || 'N/A'}</p>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div><strong>Status:</strong> ${renderStatusBadge(item)}</div>
                                <p><strong>Model:</strong> ${item.model_number || 'N/A'}</p>
                                <p><strong>Serial:</strong> ${item.serial_number || 'N/A'}</p>
                                <p><strong>Location:</strong> ${item.location_name || 'N/A'}</p>
                                <p><strong>Manufacturer:</strong> ${item.manufacturer || 'N/A'}</p>
                                <p><strong>Quantity:</strong> ${item.quantity}</p>
                            </div>
                            <div class="mt-4 pt-4 border-t">
                                 <h3 class="font-bold">Specifications</h3>
                                 <p class="text-gray-700 whitespace-pre-wrap">${item.specifications || 'None'}</p>
                            </div>
                             <div class="mt-4 pt-4 border-t">
                                 <h3 class="font-bold">Comments</h3>
                                 <p class="text-gray-700 whitespace-pre-wrap">${item.comment || 'None'}</p>
                            </div>
                            ${kitDetailsHtml}
                            ${maintenanceHistory}
                        </div>
                    </div>
                    <div>
                        <div class="card text-center">
                            <h3 class="font-bold mb-2">Item QR Code</h3>
                             <img src="${qrCodeUrl}" alt="QR Code" class="mx-auto max-w-full h-auto bg-white p-2 rounded-lg">
                            <a href="/qr/${item.id}" target="_blank" class="text-sm text-sky-600 hover:underline mt-2 inline-block">Open in new tab</a>
                        </div>
                         <div class="card mt-6">
                             <h3 class="font-bold mb-2">Actions</h3>
                             ${actionBox}
                             ${item.status !== 'Under Maintenance' ? maintenanceBox : ''}
                         </div>
                    </div>
                </div>
            `;
            res.send(renderPage(req, item.name, req.session.user, content));
        });
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
        db.all('SELECT id, name FROM items WHERE id != ? AND is_kit = 0 ORDER BY name', [itemId], (err, all_items) => {
        db.all('SELECT i.id, i.name FROM items i JOIN kits k ON i.id = k.item_id WHERE k.kit_id = ?', [itemId], (err, kit_components) => {
        db.all('SELECT DISTINCT manufacturer FROM items WHERE manufacturer IS NOT NULL AND manufacturer != "" ORDER BY manufacturer', (err, manufacturers) => {
        db.all('SELECT DISTINCT condition FROM items WHERE condition IS NOT NULL AND condition != "" ORDER BY condition', (err, conditions) => {
            
            const locationsOptions = locations.map(l => `<option value="${l.id}" ${item.location_id === l.id ? 'selected' : ''}>${l.name}</option>`).join('');
            const manufacturersDatalist = manufacturers.map(m => `<option value="${m.manufacturer}"></option>`).join('');
            const conditionsDatalist = conditions.map(c => `<option value="${c.condition}"></option>`).join('');

            const componentIds = kit_components.map(c => c.id);
            const availableItemsForKit = all_items.filter(i => !componentIds.includes(i.id));
            const allItemsOptions = availableItemsForKit.map(i => `<option value="${i.id}">${i.name}</option>`).join('');

            let kitManagementHtml = '';
            if (item.is_kit) {
                kitManagementHtml = `
                <div class="md:col-span-2 pt-6 mt-6 border-t">
                    <h3 class="text-xl font-bold mb-4">Manage Kit Components</h3>
                    <div class="card bg-gray-50">
                        <h4 class="font-bold mb-2">Current Components</h4>
                        ${kit_components.length > 0 ? `
                        <ul class="mb-4 space-y-2">
                            ${kit_components.map(c => `
                            <li class="flex justify-between items-center p-2 bg-white rounded shadow-sm">
                                <span>${c.name}</span>
                                <form action="/inventory/kit/remove/${item.id}/${c.id}" method="POST" onsubmit="return confirm('Remove this component?')">
                                    <button type="submit" class="text-red-500 hover:underline text-sm font-semibold">Remove</button>
                                </form>
                            </li>`).join('')}
                        </ul>
                        `: '<p class="text-gray-600 mb-4">No components assigned yet.</p>'}
                        
                        <h4 class="font-bold mb-2">Add New Component</h4>
                        <form action="/inventory/kit/add/${item.id}" method="POST" class="flex flex-col sm:flex-row gap-2">
                            <select name="item_id" class="flex-grow p-2 border rounded">
                                ${allItemsOptions.length > 0 ? allItemsOptions : '<option disabled>No other items available</option>'}
                            </select>
                            <button type="submit" class="btn btn-secondary">Add</button>
                        </form>
                    </div>
                </div>
                `;
            }

            const content = `
                <div class="card max-w-4xl mx-auto">
                    <form action="/inventory/edit/${itemId}" method="POST" enctype="multipart/form-data">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div><label class="block">Name*</label><input type="text" name="name" value="${item.name}" class="w-full p-2 border rounded" required></div>
                            <div><label class="block">Category</label><input type="text" name="category" value="${item.category || ''}" class="w-full p-2 border rounded"></div>
                            <div><label class="block">Model Number</label><input type="text" name="model_number" value="${item.model_number || ''}" class="w-full p-2 border rounded"></div>
                            <div><label class="block">Serial Number</label><input type="text" name="serial_number" value="${item.serial_number || ''}" class="w-full p-2 border rounded"></div>
                            
                            <div>
                                <label class="block">Manufacturer/Supplier</label>
                                <input type="text" name="manufacturer" value="${item.manufacturer || ''}" list="manufacturer-list" class="w-full p-2 border rounded">
                                <datalist id="manufacturer-list">${manufacturersDatalist}</datalist>
                            </div>
                            <div>
                                <label class="block">Condition</label>
                                <input type="text" name="condition" value="${item.condition || ''}" list="condition-list" class="w-full p-2 border rounded">
                                <datalist id="condition-list">${conditionsDatalist}</datalist>
                            </div>

                            <div><label class="block">Location</label><select name="location_id" class="w-full p-2 border rounded">${locationsOptions}</select></div>
                            <div><label class="block">Total Quantity</label><input type="number" name="quantity" value="${item.quantity}" min="1" class="w-full p-2 border rounded"></div>
                            <div class="md:col-span-2"><label class="block">Specifications</label><textarea name="specifications" class="w-full p-2 border rounded">${item.specifications || ''}</textarea></div>
                            <div class="md:col-span-2"><label class="block">Comment</label><textarea name="comment" class="w-full p-2 border rounded">${item.comment || ''}</textarea></div>
                            <div>
                                <label class="block">Image</label>
                                <input type="file" name="itemImage" class="w-full p-2 border rounded">
                                <p class="text-sm text-gray-500">Current: <a href="${item.image_url || '#'}" class="text-sky-600">${item.image_url ? 'View Image' : 'None'}</a></p>
                            </div>
                             <div class="flex items-center gap-2">
                               <input type="checkbox" name="is_kit" id="is_kit" value="1" ${item.is_kit ? 'checked' : ''} class="h-4 w-4 rounded border-gray-300 text-sky-600 focus:ring-sky-500">
                               <label for="is_kit">This item is a kit</label>
                            </div>
                            ${kitManagementHtml}
                        </div>
                        <div class="mt-6"><button type="submit" class="btn btn-primary">Save Changes</button></div>
                    </form>
                </div>
            `;
            res.send(renderPage(req, `Edit: ${item.name}`, req.session.user, content));
        });
        });
        });
        });
        });
    });
});

app.post('/inventory/edit/:id', requireRole(['admin', 'manager']), upload.single('itemImage'), (req, res) => {
    const itemId = req.params.id;
    const { name, quantity, model_number, serial_number, manufacturer, category, condition, specifications, location_id, comment } = req.body;
    const is_kit = req.body.is_kit ? 1 : 0;
    const finalSerialNumber = serial_number && serial_number.trim() !== '' ? serial_number.trim() : null;
    
    let imageUrlSql = '';
    let imageUrlParams = [];
    if (req.file) {
        imageUrlSql = ', image_url = ?';
        imageUrlParams.push(`/uploads/images/${req.file.filename}`);
    }

    const sql = `UPDATE items SET 
        name = ?, quantity = ?, model_number = ?, serial_number = ?, manufacturer = ?, 
        category = ?, condition = ?, specifications = ?, location_id = ?, comment = ?, is_kit = ?
        ${imageUrlSql} 
        WHERE id = ?`;
    
    const params = [name, quantity, model_number, finalSerialNumber, manufacturer, category, condition, specifications, location_id, comment, is_kit, ...imageUrlParams, itemId];

    db.run(sql, params, function(err) {
        if (err) {
            req.session.error = `Failed to update item. Error: ${err.message}`;
        } else {
            if (!is_kit) {
                // If it's no longer a kit, remove all component associations
                db.run('DELETE FROM kits WHERE kit_id = ?', [itemId]);
            }
            logAction(req.session.user, 'Updated Item', { id: itemId, name: name }, '', req.ip);
            req.session.success = "Item updated successfully.";
        }
        res.redirect(`/inventory/view/${itemId}`);
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

// Kit Management Routes
app.post('/inventory/kit/add/:kitId', requireRole(['admin', 'manager']), (req, res) => {
    const { kitId } = req.params;
    const { item_id } = req.body;
    db.run('INSERT INTO kits (kit_id, item_id) VALUES (?, ?)', [kitId, item_id], function(err) {
        if (err) {
            req.session.error = "Failed to add component. It might already be in the kit.";
        } else {
            logAction(req.session.user, 'Added Kit Component', {id: kitId}, `Added item ID ${item_id}`, req.ip);
            req.session.success = "Component added to kit.";
        }
        res.redirect(`/inventory/edit/${kitId}`);
    });
});

app.post('/inventory/kit/remove/:kitId/:itemId', requireRole(['admin', 'manager']), (req, res) => {
    const { kitId, itemId } = req.params;
    db.run('DELETE FROM kits WHERE kit_id = ? AND item_id = ?', [kitId, itemId], function(err) {
        if (err) {
            req.session.error = "Failed to remove component.";
        } else {
            logAction(req.session.user, 'Removed Kit Component', {id: kitId}, `Removed item ID ${itemId}`, req.ip);
            req.session.success = "Component removed from kit.";
        }
        res.redirect(`/inventory/edit/${kitId}`);
    });
});

// Check-in / Check-out Logic
app.post('/inventory/checkout/:id', requireLogin, (req, res) => {
    const itemId = req.params.id;
    const userId = req.session.user.id;

    db.get('SELECT * FROM items WHERE id = ?', [itemId], (err, item) => {
        if (err || !item) {
            req.session.error = "Item not found.";
            return res.redirect(req.get('referer') || '/inventory');
        }

        const itemsToCheckOut = [item];
        
        const processCheckout = () => {
            db.serialize(() => {
                db.run('BEGIN TRANSACTION');
                let hadError = false;
                itemsToCheckOut.forEach(thing => {
                    if (hadError) return;
                    const newQuantityCheckedOut = thing.quantity_checked_out + 1;
                    const newStatus = newQuantityCheckedOut >= thing.quantity ? 'Checked Out' : 'Available';
                    db.run('UPDATE items SET quantity_checked_out = ?, status = ?, last_activity_date = CURRENT_TIMESTAMP, checked_out_by_id = ? WHERE id = ?', 
                        [newQuantityCheckedOut, newStatus, userId, thing.id], function(err) {
                        if (err) hadError = true;
                    });
                });
                
                if (hadError) {
                    db.run('ROLLBACK');
                    req.session.error = `A database error occurred during checkout.`;
                    res.redirect(req.get('referer') || '/inventory');
                } else {
                    db.run('COMMIT', (err) => {
                        if (err) {
                            db.run('ROLLBACK');
                            req.session.error = `A database error occurred during checkout.`;
                        } else {
                            logAction(req.session.user, item.is_kit ? 'Checked Out Kit' : 'Checked Out Item', item, '', req.ip);
                            req.session.success = `"${item.name}" checked out successfully.`;
                        }
                        res.redirect(req.get('referer') || '/inventory');
                    });
                }
            });
        };

        if (item.is_kit) {
            db.all('SELECT * FROM items i JOIN kits k ON i.id = k.item_id WHERE k.kit_id = ?', [itemId], (err, components) => {
                const unavailable = components.find(c => c.quantity_checked_out >= c.quantity);
                if (unavailable) {
                    req.session.error = `Cannot check out kit. Component "${unavailable.name}" is not available.`;
                    return res.redirect(req.get('referer') || `/inventory/view/${itemId}`);
                }
                itemsToCheckOut.push(...components);
                processCheckout();
            });
        } else {
            if (item.quantity_checked_out >= item.quantity) {
                req.session.error = `"${item.name}" is not available for checkout.`;
                return res.redirect(req.get('referer') || `/inventory/view/${itemId}`);
            }
            processCheckout();
        }
    });
});

app.post('/inventory/checkin/:id', requireLogin, (req, res) => {
    const itemId = req.params.id;

    db.get('SELECT * FROM items WHERE id = ?', [itemId], (err, item) => {
        if (err || !item) {
            req.session.error = "Item not found.";
            return res.redirect(req.get('referer') || '/inventory');
        }
        if (item.quantity_checked_out <= 0) {
            req.session.error = `Cannot check in "${item.name}". It is already fully checked in.`;
            return res.redirect(req.get('referer') || `/inventory/view/${itemId}`);
        }

        const itemsToCheckIn = [item];

        const processCheckin = () => {
             db.serialize(() => {
                db.run('BEGIN TRANSACTION');
                let hadError = false;

                itemsToCheckIn.forEach(thing => {
                    if(hadError) return;
                    
                    const newQuantityCheckedOut = Math.max(0, thing.quantity_checked_out - 1);
                    // When an item is checked in, it should become 'Available' unless it's still fully checked out
                    // which is impossible during a check-in. This correctly handles multi-quantity items.
                    const newStatus = 'Available'; 
                    
                    // If the new checked-out quantity is 0, clear the user association. Otherwise, leave it.
                    let updateSql = `UPDATE items 
                                     SET quantity_checked_out = ?, 
                                         status = ?, 
                                         last_activity_date = CURRENT_TIMESTAMP, 
                                         checked_out_by_id = CASE WHEN ? = 0 THEN NULL ELSE checked_out_by_id END 
                                     WHERE id = ?`;
                    let params = [newQuantityCheckedOut, newStatus, newQuantityCheckedOut, thing.id];

                    db.run(updateSql, params, function(err) {
                        if (err) hadError = true;
                    });
                });
                
                if (hadError) {
                     db.run('ROLLBACK');
                     req.session.error = `A database error occurred during check-in.`;
                     res.redirect(req.get('referer') || '/inventory');
                } else {
                    db.run('COMMIT', (err) => {
                        if (err) {
                           db.run('ROLLBACK');
                           req.session.error = `A database error occurred during check-in.`;
                        } else {
                            logAction(req.session.user, item.is_kit ? 'Checked In Kit' : 'Checked In Item', item, '', req.ip);
                            req.session.success = `"${item.name}" checked in successfully.`;
                        }
                        res.redirect(req.get('referer') || '/inventory');
                    });
                }
            });
        };
        
        if (item.is_kit) {
            db.all('SELECT * FROM items i JOIN kits k ON i.id = k.item_id WHERE k.kit_id = ?', [itemId], (err, components) => {
                itemsToCheckIn.push(...components);
                processCheckin();
            });
        } else {
            processCheckin();
        }
    });
});


// --- Maintenance ---
app.post('/maintenance/report/:id', requireLogin, (req, res) => {
    const itemId = req.params.id;
    const { description } = req.body;
    db.run('INSERT INTO maintenance_log (item_id, user_id, description) VALUES (?, ?, ?)', [itemId, req.session.user.id, description], function(err) {
        if (err) {
            req.session.error = "Failed to report issue.";
            res.redirect(`/inventory/view/${itemId}`);
        } else {
            db.run("UPDATE items SET status = 'Under Maintenance' WHERE id = ?", [itemId], () => {
                db.get('SELECT name FROM items WHERE id = ?', [itemId], (err, item) => {
                    logAction(req.session.user, 'Reported Maintenance', item, description, req.ip);
                    req.session.success = "Maintenance issue reported. Item status has been updated.";
                    res.redirect(`/inventory/view/${itemId}`);
                });
            });
        }
    });
});

app.post('/maintenance/resolve/:log_id', requireRole(['admin', 'manager']), (req, res) => {
    const { log_id } = req.params;
    const { resolution_notes } = req.body;

    db.get("SELECT item_id FROM maintenance_log WHERE id = ?", [log_id], (err, log) => {
        if (err || !log) {
            req.session.error = "Maintenance log not found.";
            return res.redirect('/inventory');
        }

        const sql = "UPDATE maintenance_log SET resolved_date = CURRENT_TIMESTAMP, resolution_notes = ? WHERE id = ?";
        db.run(sql, [resolution_notes, log_id], (err) => {
            if (err) {
                req.session.error = "Failed to resolve maintenance issue.";
                return res.redirect(`/inventory/view/${log.item_id}`);
            }

            db.get("SELECT id FROM maintenance_log WHERE item_id = ? AND resolved_date IS NULL", [log.item_id], (err, other_log) => {
                if (!other_log) { // Only change status if no other open maintenance logs exist for this item
                     db.get('SELECT quantity_checked_out, quantity FROM items WHERE id = ?', [log.item_id], (err, item) => {
                        const newStatus = (item && item.quantity_checked_out >= item.quantity) ? 'Checked Out' : 'Available';
                        db.run("UPDATE items SET status = ? WHERE id = ?", [newStatus, log.item_id]);
                    });
                }
                db.get('SELECT name FROM items WHERE id = ?', [log.item_id], (err, item) => {
                    logAction(req.session.user, 'Resolved Maintenance', item, resolution_notes, req.ip);
                    req.session.success = "Maintenance issue has been resolved.";
                    res.redirect(`/inventory/view/${log.item_id}`);
                });
            });
        });
    });
});

// --- Purchase Requests ---
app.get('/requests/new', requireLogin, (req, res) => {
    const content = `
        <div class="card max-w-2xl mx-auto">
            <form action="/requests/new" method="POST">
                <div class="mb-4">
                    <label for="item_name" class="block font-bold text-gray-700">Item Name*</label>
                    <input type="text" name="item_name" id="item_name" class="w-full p-2 border rounded" required>
                </div>
                <div class="mb-4">
                    <label for="link" class="block font-bold text-gray-700">Link to Purchase (optional)</label>
                    <input type="url" name="link" id="link" class="w-full p-2 border rounded" placeholder="https://example.com/item">
                </div>
                <div class="mb-4">
                    <label for="reason" class="block font-bold text-gray-700">Reason for Request*</label>
                    <textarea name="reason" id="reason" class="w-full p-2 border rounded" rows="4" required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Submit Request</button>
            </form>
        </div>
    `;
    res.send(renderPage(req, 'Request New Item', req.session.user, content));
});

app.post('/requests/new', requireLogin, (req, res) => {
    const { item_name, link, reason } = req.body;
    const requested_by_id = req.session.user.id;

    const sql = 'INSERT INTO purchase_requests (requested_by_id, item_name, link, reason) VALUES (?, ?, ?, ?)';
    db.run(sql, [requested_by_id, item_name, link, reason], function(err) {
        if (err) {
            req.session.error = "Failed to submit purchase request.";
            res.redirect('/requests/new');
        } else {
            logAction(req.session.user, 'Submitted Purchase Request', null, `Item: ${item_name}`, req.ip);
            req.session.success = "Purchase request submitted successfully.";
            res.redirect('/dashboard');
        }
    });
});


// --- Reservations ---
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
                <div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
                    <div class="xl:col-span-2 card">
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
                                <input type="date" name="start_date" id="start_date" class="w-full p-2 border rounded" required>
                            </div>
                             <div class="mb-4">
                                <label class="block">End Date</label>
                                <input type="date" name="end_date" id="end_date" class="w-full p-2 border rounded" required>
                                <p class="text-sm text-gray-500 mt-1">Max reservation: ${RESERVATION_LIMIT_DAYS} days.</p>
                            </div>
                            <button type="submit" class="btn btn-primary w-full">Reserve Item</button>
                        </form>
                    </div>
                </div>
                <script>
                    const startDateInput = document.getElementById('start_date');
                    const endDateInput = document.getElementById('end_date');
                    
                    startDateInput.addEventListener('change', () => {
                        if (!startDateInput.value) return;
                        
                        const startDate = new Date(startDateInput.value + 'T00:00:00');
                        endDateInput.min = startDateInput.value;
                        
                        const maxDate = new Date(startDate);
                        maxDate.setDate(startDate.getDate() + ${RESERVATION_LIMIT_DAYS - 1});
                        
                        const maxDateString = maxDate.toISOString().split('T')[0];
                        endDateInput.max = maxDateString;
                    });
                </script>
            `;
            res.send(renderPage(req, 'Reservations Calendar', req.session.user, content));
        });
    });
});

app.post('/reservations', requireLogin, (req, res) => {
    const { item_id, start_date, end_date } = req.body;
    
    const startDate = new Date(start_date);
    const endDate = new Date(end_date);
    const diffTime = Math.abs(endDate - startDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;

    if (diffDays > RESERVATION_LIMIT_DAYS) {
        req.session.error = `Reservation cannot be longer than ${RESERVATION_LIMIT_DAYS} days.`;
        return res.redirect('/reservations');
    }
    
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
                res.redirect('/reservations');
            } else {
                db.get('SELECT name FROM items WHERE id = ?', [item_id], (err, item) => {
                    req.session.success = "Reservation created successfully.";
                    logAction(req.session.user, 'Created Reservation', item, `For ${start_date} to ${end_date}`, req.ip);
                    res.redirect('/reservations');
                });
            }
        });
    });
});

app.get('/my-reservations', requireLogin, (req, res) => {
    const sql = `
        SELECT r.*, i.name as item_name 
        FROM reservations r
        JOIN items i ON r.item_id = i.id
        WHERE r.user_id = ?
        ORDER BY r.start_date DESC
    `;
    db.all(sql, [req.session.user.id], (err, my_reservations) => {
        if (err) {
            req.session.error = "Could not load your reservations.";
            return res.redirect('/dashboard');
        }
        
        const reservationsHtml = my_reservations.map(r => {
            const today = new Date();
            const endDate = new Date(r.end_date);
            const canRequestExtension = r.status === 'Active' && endDate >= today;

            let extensionHtml = '';
            if (canRequestExtension) {
                if (r.extension_status === 'None' || r.extension_status === 'Denied') {
                     extensionHtml = `
                        <form action="/reservations/request-extension/${r.id}" method="POST" class="mt-2">
                             <input type="date" name="new_end_date" class="p-1 border rounded" required min="${r.end_date}">
                             <textarea name="reason" class="w-full p-1 border rounded mt-1" placeholder="Reason for extension..."></textarea>
                             <button type="submit" class="btn btn-secondary text-sm mt-1">Request Extension</button>
                        </form>
                    `;
                } else if (r.extension_status === 'Pending') {
                    extensionHtml = '<p class="mt-2 text-yellow-600 font-semibold">Extension request pending review.</p>';
                } else if (r.extension_status === 'Approved') {
                     extensionHtml = '<p class="mt-2 text-green-600 font-semibold">Extension approved!</p>';
                }
            }

            return `
                <div class="card mb-4">
                    <h3 class="text-lg font-bold">${r.item_name}</h3>
                    <p><strong>From:</strong> ${r.start_date} <strong>To:</strong> ${r.end_date}</p>
                    <p><strong>Status:</strong> ${r.status}</p>
                    ${extensionHtml}
                </div>
            `;
        }).join('');

        const content = `<div>${my_reservations.length > 0 ? reservationsHtml : '<p>You have no reservations.</p>'}</div>`;
        res.send(renderPage(req, 'My Reservations', req.session.user, content));
    });
});

app.post('/reservations/request-extension/:id', requireLogin, (req, res) => {
    const { id } = req.params;
    const { new_end_date, reason } = req.body;
    
    const sql = "UPDATE reservations SET requested_end_date = ?, extension_reason = ?, extension_status = 'Pending' WHERE id = ? AND user_id = ?";
    db.run(sql, [new_end_date, reason, id, req.session.user.id], function(err) {
        if (err || this.changes === 0) {
            req.session.error = "Failed to request extension. It may not be your reservation.";
        } else {
            logAction(req.session.user, 'Requested Extension', null, `Reservation ID: ${id}`, req.ip);
            req.session.success = "Extension request submitted successfully.";
        }
        res.redirect('/my-reservations');
    });
});

app.post('/reservations/cancel/:id', requireLogin, (req, res) => {
    const reservationId = req.params.id;
    db.get('SELECT r.user_id, i.id as item_id, i.name as item_name FROM reservations r JOIN items i ON r.item_id = i.id WHERE r.id = ?', [reservationId], (err, reservation) => {
        if (!reservation) {
            req.session.error = "Reservation not found.";
            return res.redirect('/reservations');
        }
        if (req.session.user.role === 'user' && req.session.user.id !== reservation.user_id) {
            req.session.error = "You can only cancel your own reservations.";
            return res.redirect('/reservations');
        }
        db.run("UPDATE reservations SET status = 'Cancelled' WHERE id = ?", [reservationId], function(err) {
            if (err) {
                req.session.error = "Failed to cancel reservation.";
            } else {
                req.session.success = "Reservation cancelled.";
                logAction(req.session.user, 'Cancelled Reservation', { id: reservation.item_id, name: reservation.item_name }, `Reservation ID: ${reservationId}`, req.ip);
            }
            res.redirect(req.get('referer') || '/my-reservations');
        });
    });
});


// --- Admin Pages ---
app.get('/reports', requireRole(['admin', 'manager']), (req, res) => {
    const queries = {
        itemsByCategory: "SELECT category, COUNT(*) as count FROM items GROUP BY category",
        itemsByLocation: "SELECT l.name as location, COUNT(i.id) as count FROM locations l LEFT JOIN items i ON l.id = i.location_id GROUP BY l.name",
        itemStatus: "SELECT status, COUNT(*) as count FROM items GROUP BY status"
    };

    db.all(queries.itemsByCategory, (err, categoryData) => {
    db.all(queries.itemsByLocation, (err, locationData) => {
    db.all(queries.itemStatus, (err, statusData) => {
        const content = `
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="card">
                    <h2 class="text-xl font-bold mb-4 text-center">Items by Category</h2>
                    <canvas id="categoryChart"></canvas>
                </div>
                 <div class="card">
                    <h2 class="text-xl font-bold mb-4 text-center">Item Status Distribution</h2>
                    <canvas id="statusChart"></canvas>
                </div>
                 <div class="card lg:col-span-2">
                    <h2 class="text-xl font-bold mb-4 text-center">Items by Location</h2>
                    <canvas id="locationChart"></canvas>
                </div>
            </div>

            <script>
                const categoryData = {
                    labels: ${JSON.stringify(categoryData.map(d => d.category || 'Uncategorized'))},
                    datasets: [{
                        label: 'Items',
                        data: ${JSON.stringify(categoryData.map(d => d.count))},
                        backgroundColor: ['#38bdf8', '#fbbf24', '#f87171', '#4ade80', '#a78bfa', '#fb923c']
                    }]
                };
                new Chart(document.getElementById('categoryChart'), { type: 'pie', data: categoryData });

                const statusData = {
                    labels: ${JSON.stringify(statusData.map(d => d.status))},
                    datasets: [{
                        label: 'Status',
                        data: ${JSON.stringify(statusData.map(d => d.count))},
                        backgroundColor: ['#4ade80', '#fbbf24', '#f87171']
                    }]
                };
                new Chart(document.getElementById('statusChart'), { type: 'doughnut', data: statusData });

                const locationData = {
                    labels: ${JSON.stringify(locationData.map(d => d.location))},
                    datasets: [{
                        label: 'Number of Items',
                        data: ${JSON.stringify(locationData.map(d => d.count))},
                        backgroundColor: '#0ea5e9'
                    }]
                };
                new Chart(document.getElementById('locationChart'), {
                    type: 'bar',
                    data: locationData,
                    options: { scales: { y: { beginAtZero: true } } }
                });
            </script>
        `;
        res.send(renderPage(req, 'Reports', req.session.user, content));
    });
    });
    });
});

app.get('/admin/requests', requireRole(['admin', 'manager']), (req, res) => {
    const sql = `
        SELECT pr.*, u_req.name as requester_name, u_rev.name as reviewer_name
        FROM purchase_requests pr
        JOIN users u_req ON pr.requested_by_id = u_req.id
        LEFT JOIN users u_rev ON pr.reviewed_by_id = u_rev.id
        ORDER BY pr.request_date DESC
    `;
    db.all(sql, [], (err, requests) => {
        if (err) {
            req.session.error = "Could not load purchase requests.";
            return res.redirect('/dashboard');
        }

        const renderRequestRow = (r) => `
            <tr class="border-b">
                <td class="p-2">${new Date(r.request_date).toLocaleDateString()}</td>
                <td class="p-2">${r.item_name}</td>
                <td class="p-2">${r.requester_name}</td>
                <td class="p-2">${r.reason} ${r.link ? `<a href="${r.link}" target="_blank" class="text-sky-600">[Link]</a>` : ''}</td>
                <td class="p-2">${r.status === 'Pending' ? 
                    `<div class="flex gap-2">
                        <form action="/admin/requests/approve/${r.id}" method="POST"><button class="btn btn-primary text-sm">Approve</button></form>
                        <form action="/admin/requests/deny/${r.id}" method="POST"><button class="btn btn-danger text-sm">Deny</button></form>
                    </div>` : 
                    `Reviewed by ${r.reviewer_name || 'N/A'}`
                }</td>
            </tr>
        `;

        const pending = requests.filter(r => r.status === 'Pending');
        const reviewed = requests.filter(r => r.status !== 'Pending');

        const content = `
            <div class="card mb-6">
                <h2 class="text-xl font-bold mb-4">Pending Requests</h2>
                <div class="overflow-x-auto">
                <table class="w-full text-left">
                    <thead><tr class="border-b-2"><th class="p-2">Date</th><th class="p-2">Item</th><th class="p-2">Requester</th><th class="p-2">Reason</th><th class="p-2">Action</th></tr></thead>
                    <tbody>
                        ${pending.length > 0 ? pending.map(renderRequestRow).join('') : '<tr><td colspan="5" class="p-4 text-center">No pending requests.</td></tr>'}
                    </tbody>
                </table>
                </div>
            </div>
            <div class="card">
                <h2 class="text-xl font-bold mb-4">Reviewed Requests</h2>
                <div class="overflow-x-auto">
                <table class="w-full text-left">
                    <thead><tr class="border-b-2"><th class="p-2">Date</th><th class="p-2">Item</th><th class="p-2">Requester</th><th class="p-2">Reason</th><th class="p-2">Outcome</th></tr></thead>
                    <tbody>
                         ${reviewed.length > 0 ? reviewed.map(r => `
                            <tr class="border-b">
                                <td class="p-2">${new Date(r.request_date).toLocaleDateString()}</td>
                                <td class="p-2">${r.item_name}</td>
                                <td class="p-2">${r.requester_name}</td>
                                <td class="p-2">${r.reason}</td>
                                <td class="p-2">
                                    <span class="${r.status === 'Approved' ? 'text-green-600' : 'text-red-600'} font-bold">${r.status}</span>
                                    by ${r.reviewer_name || 'N/A'}
                                </td>
                            </tr>
                         `).join('') : '<tr><td colspan="5" class="p-4 text-center">No reviewed requests.</td></tr>'}
                    </tbody>
                </table>
                </div>
            </div>
        `;
        res.send(renderPage(req, 'Purchase Requests', req.session.user, content));
    });
});

app.post('/admin/requests/:action/:id', requireRole(['admin', 'manager']), (req, res) => {
    const { action, id } = req.params;
    const reviewer_id = req.session.user.id;

    if (!['approve', 'deny'].includes(action)) {
        req.session.error = "Invalid action.";
        return res.redirect('/admin/requests');
    }

    const newStatus = action === 'approve' ? 'Approved' : 'Denied';

    const sql = 'UPDATE purchase_requests SET status = ?, reviewed_by_id = ?, review_date = CURRENT_TIMESTAMP WHERE id = ?';
    db.run(sql, [newStatus, reviewer_id, id], function(err) {
        if (err || this.changes === 0) {
            req.session.error = "Failed to update purchase request.";
            res.redirect('/admin/requests');
        } else {
            db.get('SELECT item_name FROM purchase_requests WHERE id = ?', [id], (err, request) => {
                 logAction(req.session.user, `Purchase Request ${newStatus}`, null, `Item: ${request.item_name}`, req.ip);
                 req.session.success = `Request has been ${newStatus.toLowerCase()}.`;
                 res.redirect('/admin/requests');
            });
        }
    });
});

app.get('/admin/all-reservations', requireRole(['admin', 'manager']), (req, res) => {
    const sql = `
        SELECT r.*, i.name as item_name, u.name as user_name 
        FROM reservations r
        JOIN items i ON r.item_id = i.id
        JOIN users u ON r.user_id = u.id
        ORDER BY r.start_date DESC
    `;
    db.all(sql, [], (err, all_reservations) => {
        const reservationsHtml = all_reservations.map(r => `
             <tr class="border-b">
                <td class="p-2">${r.item_name}</td>
                <td class="p-2">${r.user_name}</td>
                <td class="p-2">${r.start_date}</td>
                <td class="p-2">${r.end_date}</td>
                <td class="p-2">${r.status}</td>
                <td class="p-2">
                    <form action="/reservations/cancel/${r.id}" method="POST" onsubmit="return confirm('Are you sure you want to cancel this reservation?');">
                        <button type="submit" class="btn btn-danger text-sm">Cancel</button>
                    </form>
                </td>
            </tr>
        `).join('');

        const content = `
        <div class="card">
            <table class="w-full text-left">
                <thead><tr class="border-b-2">
                    <th class="p-2">Item</th>
                    <th class="p-2">User</th>
                    <th class="p-2">Start Date</th>
                    <th class="p-2">End Date</th>
                    <th class="p-2">Status</th>
                    <th class="p-2">Actions</th>
                </tr></thead>
                <tbody>${all_reservations.length > 0 ? reservationsHtml : '<tr><td colspan="6" class="text-center p-4">No reservations found.</td></tr>'}</tbody>
            </table>
        </div>`;
        res.send(renderPage(req, 'All Reservations', req.session.user, content));
    });
});

app.get('/admin/extensions', requireRole(['admin', 'manager']), (req, res) => {
    const sql = `
        SELECT r.*, u.name as user_name, i.name as item_name
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        JOIN items i ON r.item_id = i.id
        WHERE r.extension_status = 'Pending'
        ORDER BY r.start_date
    `;
    db.all(sql, (err, requests) => {
        const requestsHtml = requests.map(r => `
            <tr class="border-b">
                <td class="p-2">${r.item_name}</td>
                <td class="p-2">${r.user_name}</td>
                <td class="p-2">${r.end_date}</td>
                <td class="p-2 font-bold text-sky-700">${r.requested_end_date}</td>
                <td class="p-2">${r.extension_reason || 'N/A'}</td>
                <td class="p-2">
                    <div class="flex gap-2">
                        <form action="/admin/extensions/approve/${r.id}" method="POST">
                             <button type="submit" class="btn btn-primary text-sm">Approve</button>
                        </form>
                         <form action="/admin/extensions/deny/${r.id}" method="POST">
                             <button type="submit" class="btn btn-danger text-sm">Deny</button>
                        </form>
                    </div>
                </td>
            </tr>
        `).join('');

        const content = `
            <div class="card">
                <table class="w-full text-left">
                    <thead><tr class="border-b-2">
                        <th class="p-2">Item</th>
                        <th class="p-2">User</th>
                        <th class="p-2">Current End Date</th>
                        <th class="p-2">Requested End Date</th>
                        <th class="p-2">Reason</th>
                        <th class="p-2">Actions</th>
                    </tr></thead>
                    <tbody>${requests.length > 0 ? requestsHtml : '<tr><td colspan="6" class="text-center p-4">No pending extension requests.</td></tr>'}</tbody>
                </table>
            </div>
        `;
        res.send(renderPage(req, 'Extension Requests', req.session.user, content));
    });
});

app.post('/admin/extensions/:action/:id', requireRole(['admin', 'manager']), (req, res) => {
    const { action, id } = req.params;
    
    db.get("SELECT * FROM reservations WHERE id = ?", [id], (err, reservation) => {
        if (err || !reservation) {
            req.session.error = "Reservation not found.";
            return res.redirect('/admin/extensions');
        }

        if (action === 'approve') {
            const conflictSql = `SELECT id FROM reservations WHERE item_id = ? AND id != ? AND status = 'Active' AND (
                (start_date <= ? AND end_date >= ?) OR (start_date BETWEEN ? AND ?)
            )`;
            db.get(conflictSql, [reservation.item_id, id, reservation.end_date, reservation.end_date, reservation.requested_end_date], (err, conflict) => {
                 if (conflict) {
                    req.session.error = `Cannot approve extension. Item is already booked by someone else during the requested extension period.`;
                    return res.redirect('/admin/extensions');
                }
                
                const updateSql = "UPDATE reservations SET end_date = ?, extension_status = 'Approved' WHERE id = ?";
                db.run(updateSql, [reservation.requested_end_date, id], (err) => {
                    if (err) req.session.error = "Failed to approve extension.";
                    else {
                        req.session.success = "Extension approved.";
                        logAction(req.session.user, 'Approved Extension', null, `Reservation ID: ${id}`, req.ip);
                    }
                    res.redirect('/admin/extensions');
                });
            });
        } else { // Deny
            const updateSql = "UPDATE reservations SET extension_status = 'Denied' WHERE id = ?";
            db.run(updateSql, [id], (err) => {
                if (err) req.session.error = "Failed to deny extension.";
                else {
                    req.session.success = "Extension denied.";
                    logAction(req.session.user, 'Denied Extension', null, `Reservation ID: ${id}`, req.ip);
                }
                res.redirect('/admin/extensions');
            });
        }
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
            let actions = u.role === 'admin' ? 'N/A' : `<a href="/users/view/${u.id}" class="text-sky-600 hover:underline">Details</a>`;
            
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
    
    db.get("SELECT role, name FROM users WHERE id = ?", [userId], (err, userToUpdate) => {
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
                logAction(req.session.user, 'Updated User Role', null, `Set user ${userToUpdate.name} to ${role}`, req.ip);
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
        if(err || this.changes === 0) { req.session.error = "Failed to time out user (user might be an admin)."; }
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
         if(err || this.changes === 0) { req.session.error = "Failed to ban user (user might be an admin)."; }
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

app.post('/users/delete/:id', requireRole(['admin']), (req, res) => {
    const userIdToDelete = req.params.id;
    const adminUserId = req.session.user.id;

    if (userIdToDelete == adminUserId) {
        req.session.error = "You cannot delete your own account.";
        return res.redirect('/users');
    }

    db.get('SELECT * FROM users WHERE id = ?', [userIdToDelete], (err, user) => {
        if (err || !user) {
            req.session.error = "User not found.";
            return res.redirect('/users');
        }
        if (user.role === 'admin') {
            req.session.error = "Administrators cannot be deleted.";
            return res.redirect(`/users/view/${userIdToDelete}`);
        }
        db.get('SELECT id, name FROM items WHERE checked_out_by_id = ?', [userIdToDelete], (err, item) => {
            if (err) {
                req.session.error = "Database error while checking for checked-out items.";
                return res.redirect(`/users/view/${userIdToDelete}`);
            }
            if (item) {
                req.session.error = `Cannot delete user. They still have item "${item.name}" checked out. Please check in all items first.`;
                return res.redirect(`/users/view/${userIdToDelete}`);
            }

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
            db.get('SELECT id FROM password_resets WHERE user_id = ? AND status = ?', [user.id, 'Pending'], (err, existing) => {
                if(!existing) {
                    db.run('INSERT INTO password_resets (user_id, status) VALUES (?, ?)', [user.id, 'Pending']);
                }
            });
        }
        req.session.success = "If your account exists, a password reset request has been sent to the administrator.";
        res.redirect('/login');
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
            <div class="overflow-x-auto">
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
            </div>
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
            const sql = `INSERT INTO items (name, category, model_number, serial_number, manufacturer, condition, quantity, last_activity_date) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`;
            
            db.serialize(() => {
                db.run('BEGIN TRANSACTION');
                const stmt = db.prepare(sql);
                items.forEach(item => {
                    const sn = item.serial_number && item.serial_number.trim() !== '' ? item.serial_number.trim() : `MBSH-${Date.now()}-${Math.random()}`;
                    stmt.run([item.name, item.category, item.model_number, sn, item.manufacturer, item.condition, item.quantity]);
                });
                stmt.finalize((err) => {
                    if (err) {
                        db.run('ROLLBACK');
                        req.session.error = `Import failed: ${err.message}. A serial number might be duplicated. No items were imported.`;
                        fs.unlinkSync(req.file.path);
                        res.redirect('/data');
                    } else {
                        db.run('COMMIT', (err) => {
                            if (err) {
                                db.run('ROLLBACK');
                                req.session.error = `Transaction failed: ${err.message}. No items were imported.`;
                            } else {
                                logAction(req.session.user, 'Imported Data', null, `Imported ${rowCount} items from CSV.`, req.ip);
                                req.session.success = `Successfully processed ${rowCount} items from CSV.`;
                            }
                            fs.unlinkSync(req.file.path);
                            res.redirect('/inventory');
                        });
                    }
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


