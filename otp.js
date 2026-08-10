const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

const USERS_FILE = path.join(__dirname, 'users.json');
const ALLOWED_DOMAIN = '@student.edu.vn';
const EMAIL_SALT = 'test_minecraft_secret_salt_2026';

// --- IN-MEMORY TEMPORARY STORAGE (RAM ONLY - ZERO DISK STORAGE FOR EMAILS) ---
const activeOtps = new Map();       // Stores active OTPs and attempt counters
const sessionTokens = new Map();    // Stores temporary login sessions
const requestHistory = new Map();   // Stores rate-limiting timestamps per hashed email
let dailyRequestCount = 0;
let lastResetDate = new Date().toISOString().split('T')[0];

function hashEmail(email) {
  return crypto
    .createHash('sha256')
    .update(email.trim().toLowerCase() + EMAIL_SALT)
    .digest('hex');
}

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } 
  catch (e) { return {}; }
}

function saveUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// 1. GENERATE OTP
app.post('/api/send-otp', (req, res) => {
  const { email } = req.body;

  const emailRegex = /^[^\s@]+@student\.edu\.vn$/i;
  if (!email || !emailRegex.test(email.trim())) {
    return res.status(400).json({ 
      success: false, 
      message: `Access restricted. Please use a valid ${ALLOWED_DOMAIN} email.` 
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const userHash = hashEmail(cleanEmail);
  const now = Date.now();
  const today = new Date().toISOString().split('T')[0];

  // Daily quota reset check
  if (lastResetDate !== today) {
    dailyRequestCount = 0;
    lastResetDate = today;
  }

  if (dailyRequestCount >= 100) {
    return res.status(429).json({
      success: false,
      message: "Daily limit reached (100 total requests). Try again tomorrow."
    });
  }

  // Cooldown check (2-minute lock per email)
  const existingOtp = activeOtps.get(userHash);
  if (existingOtp && now < existingOtp.lastSent + 2 * 60 * 1000) {
    const remainingSecs = Math.ceil((existingOtp.lastSent + 2 * 60 * 1000 - now) / 1000);
    return res.status(429).json({
      success: false,
      remainingSecs: remainingSecs,
      message: `Please wait ${remainingSecs}s before requesting a new code.`
    });
  }

  // Rate limiting check (5 per hour)
  const history = requestHistory.get(userHash) || [];
  const oneHourAgo = now - 60 * 60 * 1000;
  const recentRequests = history.filter(ts => ts > oneHourAgo);

  if (recentRequests.length >= 5) {
    const oldestRequest = recentRequests[0];
    const waitSecs = Math.ceil((oldestRequest + 60 * 60 * 1000 - now) / 1000);
    return res.status(429).json({
      success: false,
      message: `Hourly limit reached (5/hour). Please wait ${Math.ceil(waitSecs / 60)} minutes.`
    });
  }

  const otpCode = crypto.randomInt(1000, 10000).toString();

  // Save to RAM only
  activeOtps.set(userHash, {
    code: otpCode,
    expires: now + 5 * 60 * 1000,
    lastSent: now,
    attempts: 0
  });

  recentRequests.push(now);
  requestHistory.set(userHash, recentRequests);
  dailyRequestCount += 1;

  console.log(`\n========================================`);
  console.log(`[TEST MODE] OTP Code generated: ${otpCode}`);
  console.log(`========================================\n`);

  res.json({ 
    success: true, 
    remainingSecs: 120,
    message: 'OTP generated! Check terminal for code.' 
  });
});

// COOLDOWN STATUS
app.get('/api/cooldown-status', (req, res) => {
  const { email } = req.query;
  if (!email) return res.json({ remainingSecs: 0 });

  const userHash = hashEmail(email);
  const record = activeOtps.get(userHash);

  if (!record) return res.json({ remainingSecs: 0 });

  const diff = record.lastSent + 2 * 60 * 1000 - Date.now();
  if (diff > 0) {
    return res.json({ remainingSecs: Math.ceil(diff / 1000) });
  }

  res.json({ remainingSecs: 0 });
});

// 2. VERIFY OTP
app.post('/api/verify-otp', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ success: false, message: 'Missing credentials.' });

  const userHash = hashEmail(email);
  const record = activeOtps.get(userHash);

  if (!record) return res.status(400).json({ success: false, message: 'No code requested!' });

  if (Date.now() > record.expires) {
    activeOtps.delete(userHash);
    return res.status(400).json({ success: false, message: 'Code expired!' });
  }

  if (record.attempts >= 10) {
    activeOtps.delete(userHash);
    return res.status(429).json({ success: false, message: 'Too many attempts.' });
  }

  if (record.code !== code.trim()) {
    record.attempts += 1;
    return res.status(400).json({ success: false, message: 'Incorrect code!' });
  }

  // Clear OTP from RAM upon successful verification
  activeOtps.delete(userHash);

  const sessionToken = crypto.randomBytes(32).toString('hex');
  sessionTokens.set(sessionToken, {
    userHash: userHash,
    expires: Date.now() + 15 * 60 * 1000
  });

  res.json({
    success: true,
    message: 'Verified!',
    token: sessionToken
  });
});

// 3. CHECK STATUS
app.get('/api/status', (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ success: false, message: 'Email query missing.' });

  const userHash = hashEmail(email);
  const users = loadUsers();
  const user = users[userHash];

  if (!user || !user.username) {
    return res.status(404).json({ success: false, message: 'User not registered yet.' });
  }

  res.json({
    success: true,
    username: user.username,
    status: user.status
  });
});

// 4. REGISTER PROFILE
app.post('/api/register-profile', (req, res) => {
  const { email, username } = req.body;
  const token = req.headers['x-session-token'];

  if (!email || !token) return res.status(401).json({ success: false, message: 'Unauthorized session.' });

  const userHash = hashEmail(email);
  const cleanUsername = username ? username.trim() : '';

  const session = sessionTokens.get(token);

  if (!session || session.userHash !== userHash || Date.now() > session.expires) {
    return res.status(403).json({ success: false, message: 'Session expired. Please re-login.' });
  }

  const mcUsernameRegex = /^[a-zA-Z0-9_]{3,16}$/;
  if (!mcUsernameRegex.test(cleanUsername)) {
    return res.status(400).json({ success: false, message: 'Invalid Minecraft IGN (3-16 chars).' });
  }

  const users = loadUsers();

  const isUsernameTaken = Object.values(users).some(u => 
    u.username && u.username.toLowerCase() === cleanUsername.toLowerCase()
  );

  if (isUsernameTaken) {
    return res.status(400).json({ success: false, message: 'IGN already taken by another student.' });
  }

  users[userHash] = {
    username: cleanUsername,
    status: 'pending',
    registeredAt: new Date().toISOString()
  };

  sessionTokens.delete(token);
  saveUsers(users);

  res.json({ success: true, status: 'pending', username: cleanUsername });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
