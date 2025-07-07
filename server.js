const dotenv = require('dotenv');
dotenv.config();  // ✅ Load variables BEFORE anything else

// DEBUG: Show environment variables
console.log("🔍 ENV CHECK");
console.log("GOOGLE_CLIENT_ID:", process.env.GOOGLE_CLIENT_ID);
console.log("GOOGLE_CLIENT_SECRET:", process.env.GOOGLE_CLIENT_SECRET);
console.log("SESSION_SECRET:", process.env.SESSION_SECRET);

const fs = require('fs');
const https = require('https');
const path = require('path');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const rateLimit = require('express-rate-limit');

require('./auth/passport-config'); // ✅ Import after env is loaded

let users = require('./users.json');

const app = express();

// ===== Middleware (only once) =====
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,      // cookie only over HTTPS
    httpOnly: true,    // inaccessible to JS
    sameSite: 'strict',// CSRF protection
    maxAge: 30 * 60 * 1000 // 30 minutes session timeout
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// ===== CSRF Protection =====
app.use(csurf());
app.use((req, res, next) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
    secure: true,
    httpOnly: false,  // frontend JS can read and send with requests
    sameSite: 'strict'
  });
  next();
});

// ===== Rate Limiter for Login =====
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                   // limit each IP to 5 requests per window
  message: "Too many login attempts, please try again later."
});

// JWT authentication middleware
function authenticateJWT(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send("❌ Access denied, no token provided");
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).send("❌ Invalid or expired token");
  }
}

// Role-based middleware (uses JWT)
function checkRole(...allowedRoles) {
  return function (req, res, next) {
    authenticateJWT(req, res, () => {
      if (!allowedRoles.includes(req.user.role)) {
        return res.status(403).send("🚫 Forbidden: You do not have access");
      }
      next();
    });
  };
}

// SSL Options
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, 'ssl', 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'ssl', 'cert.pem'))
};

// ======================
// ROUTES
// ======================

// Register
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (users.find(u => u.email === email)) return res.status(400).send("Email already exists.");
  const hashed = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), username, email, password: hashed, role: "user" };
  users.push(user);
  fs.writeFileSync('./users.json', JSON.stringify(users, null, 2));
  res.send('✅ User registered');
});

// Login with rate limiting
app.post('/login', loginLimiter, async (req, res, next) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(403).send("❌ Invalid credentials");
  }

  req.login(user, err => {
    if (err) return next(err);

    // Regenerate session after successful login
    req.session.regenerate(err => {
      if (err) return next(err);

      // Now issue JWT tokens and send response
      const payload = { id: user.id, role: user.role, username: user.username };
      const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
      const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

      res.cookie('token', accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000,
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.send('✅ Logged in with JWT tokens');
    });
  });
});

// Refresh token
app.post('/refresh-token', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).send("No refresh token");

  try {
    const user = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const newAccessToken = jwt.sign({ id: user.id, role: user.role, username: user.username }, process.env.JWT_SECRET, { expiresIn: '15m' });

    res.cookie('token', newAccessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

    res.send("✅ Access token refreshed");
  } catch {
    res.status(403).send("Invalid or expired refresh token");
  }
});

// Logout route
app.post('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);

    req.session.destroy(err => {
      if (err) return res.status(500).send("Logout error");

      res.clearCookie('token');
      res.clearCookie('refreshToken');
      res.send('✅ Logged out');
    });
  });
});

// Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-fail' }),
  (req, res) => res.send('✅ Logged in with Google!')
);

// Home route - public
app.get('/', (req, res) => {
  res.send('<h1>🌐 Secure Auth Server is Running!</h1><p>Try <a href="/login">/login</a> or <a href="/dashboard">/dashboard</a></p>');
});

// Test route
app.get('/test', (req, res) => {
  res.send('Test route works!');
});

// Profile route - accessible to any authenticated user
app.get('/profile', authenticateJWT, (req, res) => {
  res.json({ user: req.user });
});


// Admin-only route
app.get('/admin', checkRole('admin'), (req, res) => {
  res.send(`🛠️ Welcome Admin ${req.user.username}`);
});

// Dashboard (all authenticated users)
app.get('/dashboard', authenticateJWT, (req, res) => {
  if (req.user.role === 'admin') {
    res.send(`📊 Admin Dashboard for ${req.user.username}`);
  } else {
    res.send(`📈 User Dashboard for ${req.user.username}`);
  }
});

// Start HTTPS server
https.createServer(sslOptions, app).listen(3000, () => {
  console.log('✅ HTTPS server running at https://localhost:3000');
});
