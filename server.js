// ============================================================
// Event Registration Backend Server (SECURED)
// IT Department Freshers & Farewell 2026
// ============================================================

require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Render proxy fix
app.set('trust proxy', 1);


// ==================== SECURITY MIDDLEWARE ====================

// Helmet: Sets various HTTP headers for security
app.use(helmet({
    contentSecurityPolicy: false, // Disable CSP since our HTML loads external CDNs
    crossOriginEmbedderPolicy: false
}));

// CORS: Only allow same-origin in production
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || '*',
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-Admin-Password']
}));

// Body parser with size limit to prevent payload attacks
app.use(express.json({ limit: '10kb' }));

// Global rate limiter: 100 requests per 15 min per IP
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(globalLimiter);

// Strict rate limiter for registration: 5 per hour per IP
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Too many registration attempts. Try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Strict rate limiter for admin login: 10 per 15 min per IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Too many login attempts. Try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Block access to sensitive files (BEFORE static serving)
app.use((req, res, next) => {
    // Skip API routes
    if (req.path.startsWith('/api/')) return next();

    const blocked = ['.env', '.git', 'server.js', 'package.json', 'package-lock.json', 'database.sqlite', 'node_modules'];
    const reqPath = req.path.toLowerCase().replace(/^\//, '');
    for (const b of blocked) {
        if (reqPath === b || reqPath.startsWith(b + '/') || reqPath.startsWith('.' + b)) {
            return res.status(403).json({ error: 'Access denied.' });
        }
    }
    next();
});

// ==================== DATABASE SETUP (sql.js) ====================
const initSqlJs = require('sql.js');
let db;
const DB_PATH = path.join(__dirname, 'database.sqlite');

async function initDatabase() {
    const SQL = await initSqlJs();

    // Load existing DB or create new one
    if (fs.existsSync(DB_PATH)) {
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(fileBuffer);
        console.log('✅ Database loaded from file');
    } else {
        db = new SQL.Database();
        console.log('✅ New database created');
    }

    // Create table
    db.run(`
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    `);

    saveDatabase();
}

function saveDatabase() {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
}

// Helper to run queries and return results as array of objects
function dbAll(sql, params = []) {
    const stmt = db.prepare(sql);
    if (params.length) stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
}

function dbGet(sql, params = []) {
    const results = dbAll(sql, params);
    return results.length ? results[0] : null;
}

function dbRun(sql, params = []) {
    db.run(sql, params);
    saveDatabase();
}

// ==================== PRODUCTION EMAIL SYSTEM ====================
// Gmail SMTP — configured for cloud deployment (Render)

let gmailTransporter = null;
let emailReady = false;

async function setupEmail() {
    console.log('');
    console.log('🔧 ═══ EMAIL SETUP ═══');
    console.log(`   EMAIL_USER set: ${!!process.env.EMAIL_USER}`);
    console.log(`   EMAIL_PASS set: ${!!process.env.EMAIL_PASS}`);

    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        // Explicit SMTP config — port 587 + STARTTLS works on cloud servers (Render, etc.)
        gmailTransporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            },
            tls: {
                ciphers: 'SSLv3',
                rejectUnauthorized: false
            },
            requireTLS: true,
            connectionTimeout: 120000,
            greetingTimeout: 120000,
            socketTimeout: 120000
        });

        try {
            await gmailTransporter.verify();
            emailReady = true;
            console.log('✅ Gmail SMTP — READY');
            console.log(`   📧 Sending as: ${process.env.EMAIL_USER}`);
        } catch (err) {
            console.error('❌ Gmail SMTP — FAILED:', err.message);
            console.error('   → Check your Gmail App Password at: https://myaccount.google.com/apppasswords');
            gmailTransporter = null;
        }
    } else {
        console.log('🚫 EMAIL DISABLED — EMAIL_USER and EMAIL_PASS not set');
        console.log('   → Set them in Render Dashboard → Environment');
    }

    console.log('══════════════════════');
    console.log('');
}

async function sendEmail({ to, subject, html }) {
    const fromEmail = process.env.EMAIL_USER;
    const fromName = 'IT Dept - Freshers & Farewell 2026';

    if (!emailReady || !gmailTransporter) {
        throw new Error('Email not configured — set EMAIL_USER and EMAIL_PASS in Render Environment');
    }

    try {
        await gmailTransporter.sendMail({
            from: `"${fromName}" <${fromEmail}>`,
            to,
            subject,
            html
        });
        console.log(`📧 Email sent to: ${to}`);
        return { provider: 'gmail' };
    } catch (err) {
        console.error(`❌ Email failed for ${to}:`, err.message);
        throw new Error(`Email delivery failed: ${err.message}`);
    }
}

setupEmail();

// ==================== INPUT SANITIZATION ====================
function sanitize(str) {
    if (typeof str !== 'string') return '';
    return str.trim().replace(/[<>]/g, '').substring(0, 200);
}

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function validatePhone(phone) {
    return /^\d{10}$/.test(phone.replace(/\D/g, ''));
}

const VALID_ROLES = ['FY', 'SY', 'TY', 'Ex-TY', 'Principal', 'Teaching Faculty', 'Non-Teaching Faculty'];

// ==================== AUTH MIDDLEWARE ====================
function requireAdmin(req, res, next) {
    const pw = req.headers['x-admin-password'];
    if (!pw || pw !== process.env.ADMIN_PASSWORD) {
        // Delay response to slow brute-force
        return setTimeout(() => {
            res.status(401).json({ error: 'Unauthorized.' });
        }, 500);
    }
    next();
}

// ==================== EMAIL TEMPLATES ====================
function getApprovalEmailHTML(name, role) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0a0e17;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">
<div style="max-width:600px;margin:0 auto;background:#0f1624;border:1px solid rgba(0,245,255,0.15);border-radius:16px;overflow:hidden;">
<div style="background:linear-gradient(135deg,#00f5ff,#0a84ff,#bf5af2);padding:32px;text-align:center;">
<h1 style="margin:0;color:white;font-size:24px;font-weight:800;">✅ Registration Approved!</h1>
<p style="margin:8px 0 0;color:rgba(255,255,255,0.9);font-size:14px;">IT Department — Freshers &amp; Farewell 2026</p></div>
<div style="padding:32px;">
<p style="color:#e4eaf5;font-size:16px;line-height:1.7;margin:0 0 20px;">Hey <strong style="color:#00f5ff;">${name}</strong>! 🎉</p>
<p style="color:#7a8ba8;font-size:15px;line-height:1.7;margin:0 0 24px;">Great news! Your registration has been <span style="color:#39ff14;font-weight:600;">approved</span>. You're officially in!</p>
<div style="background:rgba(0,245,255,0.05);border:1px solid rgba(0,245,255,0.12);border-radius:12px;padding:20px;margin-bottom:24px;">
<h3 style="color:#00f5ff;font-size:13px;text-transform:uppercase;letter-spacing:2px;margin:0 0 16px;">Your Details</h3>
<table style="width:100%;border-collapse:collapse;">
<tr><td style="color:#7a8ba8;font-size:14px;padding:6px 0;">Name:</td><td style="color:#e4eaf5;font-size:14px;padding:6px 0;text-align:right;font-weight:600;">${name}</td></tr>
<tr><td style="color:#7a8ba8;font-size:14px;padding:6px 0;">Role:</td><td style="color:#e4eaf5;font-size:14px;padding:6px 0;text-align:right;font-weight:600;">${role}</td></tr>
<tr><td style="color:#7a8ba8;font-size:14px;padding:6px 0;">Status:</td><td style="color:#39ff14;font-size:14px;padding:6px 0;text-align:right;font-weight:600;">✓ Approved</td></tr>
</table></div>
<div style="background:rgba(191,90,242,0.05);border:1px solid rgba(191,90,242,0.12);border-radius:12px;padding:20px;margin-bottom:24px;">
<h3 style="color:#bf5af2;font-size:13px;text-transform:uppercase;letter-spacing:2px;margin:0 0 12px;">Quick Reminders</h3>
<ul style="color:#7a8ba8;font-size:14px;line-height:2;margin:0;padding-left:20px;">
<li>Carry your <strong style="color:#e4eaf5;">College ID</strong></li>
<li>Dress Code: <strong style="color:#e4eaf5;">Semi-Formal / Black &amp; White Theme</strong></li>
<li>Be on time — <strong style="color:#e4eaf5;">No re-entry</strong></li>
<li>No outside food or drinks</li></ul></div>
<p style="color:#7a8ba8;font-size:14px;line-height:1.7;margin:0;">Get ready for an amazing celebration! 🚀</p></div>
<div style="border-top:1px solid rgba(0,245,255,0.1);padding:20px;text-align:center;">
<p style="color:#7a8ba8;font-size:12px;margin:0;">© 2026 IT Department Student Council</p>
<p style="color:rgba(122,139,168,0.5);font-size:11px;margin:6px 0 0;">Automated email — do not reply.</p></div></div></body></html>`;
}

function getRejectionEmailHTML(name) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0a0e17;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">
<div style="max-width:600px;margin:0 auto;background:#0f1624;border:1px solid rgba(255,45,85,0.15);border-radius:16px;overflow:hidden;">
<div style="background:linear-gradient(135deg,#ff2d55,#ff9500);padding:32px;text-align:center;">
<h1 style="margin:0;color:white;font-size:24px;font-weight:800;">Registration Update</h1>
<p style="margin:8px 0 0;color:rgba(255,255,255,0.9);font-size:14px;">IT Department — Freshers &amp; Farewell 2026</p></div>
<div style="padding:32px;">
<p style="color:#e4eaf5;font-size:16px;line-height:1.7;margin:0 0 20px;">Hey <strong>${name}</strong>,</p>
<p style="color:#7a8ba8;font-size:15px;line-height:1.7;margin:0 0 24px;">We regret to inform you that your registration could not be approved at this time due to capacity limits or other reasons.</p>
<p style="color:#7a8ba8;font-size:14px;line-height:1.7;margin:0;">If you believe this is an error, please contact the event coordinators.</p></div>
<div style="border-top:1px solid rgba(255,45,85,0.1);padding:20px;text-align:center;">
<p style="color:#7a8ba8;font-size:12px;margin:0;">© 2026 IT Department Student Council</p></div></div></body></html>`;
}

// ==================== API ROUTES ====================

// --- PUBLIC: Register ---
app.post('/api/register', registerLimiter, (req, res) => {
    try {
        const name = sanitize(req.body.name);
        const email = sanitize(req.body.email).toLowerCase();
        const phone = sanitize(req.body.phone);
        const role = sanitize(req.body.role);

        if (!name || !email || !phone || !role) {
            return res.status(400).json({ error: 'All fields are required.' });
        }
        if (name.length < 2) {
            return res.status(400).json({ error: 'Name must be at least 2 characters.' });
        }
        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address.' });
        }
        if (!validatePhone(phone)) {
            return res.status(400).json({ error: 'Invalid phone number. Must be 10 digits.' });
        }
        if (!VALID_ROLES.includes(role)) {
            return res.status(400).json({ error: 'Invalid role selected.' });
        }

        // Check duplicate
        const existing = dbGet('SELECT id FROM registrations WHERE email = ?', [email]);
        if (existing) {
            return res.status(409).json({ error: 'This email is already registered.' });
        }

        dbRun(
            `INSERT INTO registrations (name, email, phone, role, status, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', datetime('now'), datetime('now'))`,
            [name, email, phone, role]
        );

        console.log(`📝 New registration: ${name} (${email}) — ${role}`);
        res.status(201).json({ success: true, message: 'Registration submitted! Pending admin approval.' });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Server error. Please try again.' });
    }
});

// --- ADMIN: Login ---
app.post('/api/admin/login', loginLimiter, (req, res) => {
    const { password } = req.body;
    if (password === process.env.ADMIN_PASSWORD) {
        res.json({ success: true });
    } else {
        setTimeout(() => res.status(401).json({ error: 'Invalid password.' }), 500);
    }
});

// --- ADMIN: Get registrations ---
app.get('/api/admin/registrations', requireAdmin, (req, res) => {
    try {
        const { status } = req.query;
        let rows;
        if (status && ['pending', 'approved', 'rejected'].includes(status)) {
            rows = dbAll('SELECT * FROM registrations WHERE status = ? ORDER BY created_at DESC', [status]);
        } else {
            rows = dbAll('SELECT * FROM registrations ORDER BY created_at DESC');
        }

        const stats = {
            total: (dbGet('SELECT COUNT(*) as count FROM registrations') || {}).count || 0,
            pending: (dbGet("SELECT COUNT(*) as count FROM registrations WHERE status = 'pending'") || {}).count || 0,
            approved: (dbGet("SELECT COUNT(*) as count FROM registrations WHERE status = 'approved'") || {}).count || 0,
            rejected: (dbGet("SELECT COUNT(*) as count FROM registrations WHERE status = 'rejected'") || {}).count || 0
        };

        res.json({ registrations: rows, stats });
    } catch (err) {
        console.error('Fetch error:', err);
        res.status(500).json({ error: 'Server error.' });
    }
});

// --- ADMIN: Approve ---
app.post('/api/admin/approve/:id', requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID.' });

        const reg = dbGet('SELECT * FROM registrations WHERE id = ?', [id]);
        if (!reg) return res.status(404).json({ error: 'Not found.' });
        if (reg.status === 'approved') return res.status(400).json({ error: 'Already approved.' });

        dbRun("UPDATE registrations SET status = 'approved', updated_at = datetime('now') WHERE id = ?", [id]);
        console.log(`✅ Approved: ${reg.name} (${reg.email})`);

        if (!emailReady) {
            return res.json({ success: true, message: 'Approved! (Email disabled — set EMAIL_USER & EMAIL_PASS in Render Environment)' });
        }
        try {
            const result = await sendEmail({
                to: reg.email,
                subject: '✅ Registration Approved — Freshers & Farewell 2026',
                html: getApprovalEmailHTML(reg.name, reg.role)
            });
            res.json({ success: true, message: `Approved & email sent to ${reg.email}` });
        } catch (emailErr) {
            console.error('Email error:', emailErr.message);
            res.json({ success: true, message: 'Approved, but email failed.', emailError: emailErr.message });
        }
    } catch (err) {
        console.error('Approve error:', err);
        res.status(500).json({ error: 'Server error.' });
    }
});

// --- ADMIN: Reject ---
app.post('/api/admin/reject/:id', requireAdmin, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID.' });

        const reg = dbGet('SELECT * FROM registrations WHERE id = ?', [id]);
        if (!reg) return res.status(404).json({ error: 'Not found.' });
        if (reg.status === 'rejected') return res.status(400).json({ error: 'Already rejected.' });

        dbRun("UPDATE registrations SET status = 'rejected', updated_at = datetime('now') WHERE id = ?", [id]);
        console.log(`❌ Rejected: ${reg.name} (${reg.email})`);

        if (!emailReady) {
            return res.json({ success: true, message: 'Rejected! (Email disabled — set EMAIL_USER & EMAIL_PASS in Render Environment)' });
        }
        try {
            const result = await sendEmail({
                to: reg.email,
                subject: 'Registration Update — Freshers & Farewell 2026',
                html: getRejectionEmailHTML(reg.name)
            });
            res.json({ success: true, message: `Rejected & email sent to ${reg.email}` });
        } catch (emailErr) {
            console.error('Email error:', emailErr.message);
            res.json({ success: true, message: 'Rejected, but email failed.', emailError: emailErr.message });
        }
    } catch (err) {
        console.error('Reject error:', err);
        res.status(500).json({ error: 'Server error.' });
    }
});

// --- ADMIN: Delete ---
app.delete('/api/admin/delete/:id', requireAdmin, (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID.' });

        const reg = dbGet('SELECT id FROM registrations WHERE id = ?', [id]);
        if (!reg) return res.status(404).json({ error: 'Not found.' });

        dbRun('DELETE FROM registrations WHERE id = ?', [id]);
        console.log(`🗑️ Deleted ID: ${id}`);
        res.json({ success: true, message: 'Deleted.' });
    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).json({ error: 'Server error.' });
    }
});

// --- Health check (for Render & monitoring) ---
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        email: emailReady ? 'configured' : 'not configured',
        emailUser: process.env.EMAIL_USER ? process.env.EMAIL_USER.substring(0, 3) + '***' : 'NOT SET',
        uptime: Math.floor(process.uptime()) + 's'
    });
});

// --- Admin: Test email (verify email works on production) ---
app.post('/api/admin/test-email', requireAdmin, async (req, res) => {
    if (!emailReady) {
        return res.status(500).json({ error: 'Email not configured. Set EMAIL_USER and EMAIL_PASS in Render Environment.' });
    }
    try {
        await sendEmail({
            to: process.env.EMAIL_USER,
            subject: '✅ Test Email — Server is Working!',
            html: '<h2>Your email system is working!</h2><p>This test was sent from your Render deployment.</p>'
        });
        res.json({ success: true, message: `Test email sent to ${process.env.EMAIL_USER}` });
    } catch (err) {
        res.status(500).json({ error: 'Email test failed: ' + err.message });
    }
});

// Catch-all 404 for unknown API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found.' });
});

// Root route - redirect to invitation page
app.get('/', (req, res) => {
    res.redirect('/invitation.html');
});

// Serve static files (AFTER API routes so they take priority)
app.use(express.static(__dirname, {
    dotfiles: 'deny'
}));

// ==================== START ====================
// Get local network IP for mobile access
function getLocalIP() {
    const os = require('os');
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'localhost';
}

initDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        const localIP = getLocalIP();
        console.log(`\n🚀 Server running!`);
        console.log(`📄 PC:     http://localhost:${PORT}/invitation.html`);
        console.log(`📱 Mobile: http://${localIP}:${PORT}/invitation.html`);
        console.log(`🔐 Admin:  http://localhost:${PORT}/admin.html`);
        console.log(`\n🛡️  Security: Helmet, Rate Limiting, Input Sanitization — ACTIVE`);
        console.log(`-------------------------------------------\n`);
    });
}).catch(err => {
    console.error('Failed to start:', err);
    process.exit(1);
});
