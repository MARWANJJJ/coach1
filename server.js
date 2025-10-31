require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'subscriptions.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-to-a-secret';

app.use(cors());
app.use(express.json());
// basic security headers
app.use(helmet());
// trust proxy if behind reverse proxy (for secure cookies / rate-limiter)
app.set('trust proxy', 1);

// rate limiter for auth endpoints to mitigate brute-force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 6, // limit each IP to 6 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: 'Too many login attempts, please try again later.' }
});
// serve static files (coach.html + assets)
app.use(express.static(__dirname));

function readData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return [];
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('readData error', err);
    return [];
  }
}

function writeData(list) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('writeData error', err);
  }
}

function readUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) return [];
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('readUsers error', err);
    return [];
  }
}

function writeUsers(list) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch (err) {
    console.error('writeUsers error', err);
  }
}

// create subscription (public)
app.post('/api/subscriptions', (req, res) => {
  const data = req.body || {};
  const list = readData();
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2,6);
  // allow client to supply endsAt (ISO) or compute from durationDays/package
  const createdAt = new Date().toISOString();
  const entry = Object.assign({ id, status: 'pending', createdAt }, data);
  // normalize endsAt if provided as Date or string
  if (entry.endsAt) {
    try { entry.endsAt = new Date(entry.endsAt).toISOString(); } catch (e) { delete entry.endsAt; }
  }
  list.unshift(entry);
  writeData(list);
  return res.status(201).json({ ok: true, entry });
});

// get subscriptions for authenticated user
app.get('/api/subscriptions/me', requireAuth, (req, res) => {
  const payload = req.user || {};
  const email = payload.email;
  if (!email) return res.status(400).json({ ok: false, message: 'no user email in token' });
  const list = readData();
  const mine = list.filter(x => x.email && x.email.toLowerCase() === String(email).toLowerCase());
  return res.json({ ok: true, list: mine });
});

// user registration
app.post('/api/users/register', async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, message: 'email & password required' });
  const users = readUsers();
  if (users.find(u => u.email === email)) return res.status(409).json({ ok: false, message: 'email already registered' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2,6);
    // if this email matches ADMIN_EMAIL, grant admin role
    const role = (ADMIN_EMAIL && email.toLowerCase() === ADMIN_EMAIL.toLowerCase()) ? 'admin' : 'user';
    const user = { id, email, name: name || '', password: hashed, createdAt: new Date().toISOString(), role };
    users.push(user);
    writeUsers(users);
    const token = jwt.sign({ email: user.email, id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '12h' });
    return res.status(201).json({ ok: true, token });
  } catch (err) {
    console.error('register error', err);
    return res.status(500).json({ ok: false, message: 'server error' });
  }
});

// user login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, message: 'email & password required' });
  const users = readUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ ok: false, message: 'invalid credentials' });
  try {
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ ok: false, message: 'invalid credentials' });
    const token = jwt.sign({ email: user.email, id: user.id, role: user.role, name: user.name || '' }, JWT_SECRET, { expiresIn: '12h' });
    return res.json({ ok: true, token });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ ok: false, message: 'server error' });
  }
});

// auth: login -> returns JWT
// apply rate limiter to login route
app.post('/api/auth/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok: false, message: 'username & password required' });
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '12h' });
    return res.json({ ok: true, token });
  }
  return res.status(401).json({ ok: false, message: 'invalid credentials' });
});

// middleware to verify token
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ ok: false, message: 'missing token' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, message: 'invalid token' });
  }
}

// get all subscriptions (admin)
app.get('/api/subscriptions', requireAuth, (req, res) => {
  // only admin user (env ADMIN_USER) or token with role 'admin' can access
  const payload = req.user || {};
  if (!(payload.username === ADMIN_USER || payload.role === 'admin')) return res.status(403).json({ ok: false, message: 'forbidden' });
  const list = readData();
  return res.json({ ok: true, list });
});

// update status (admin)
app.post('/api/subscriptions/:id/status', requireAuth, (req, res) => {
  const id = req.params.id;
  const { status } = req.body || {};
  if (!['pending','approved','rejected'].includes(status)) return res.status(400).json({ ok: false, message: 'invalid status' });
  // only admin
  const payload = req.user || {};
  if (!(payload.username === ADMIN_USER || payload.role === 'admin')) return res.status(403).json({ ok: false, message: 'forbidden' });
  const list = readData();
  const idx = list.findIndex(x => x.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, message: 'not found' });
  list[idx].status = status;
  list[idx].updatedAt = new Date().toISOString();
  writeData(list);
  return res.json({ ok: true, entry: list[idx] });
});

// simple ping
app.get('/api/ping', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
