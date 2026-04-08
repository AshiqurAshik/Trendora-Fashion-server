require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors());
app.use(express.json());

/* ================= POSTGRESQL ================= */

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

pool
  .connect()
  .then(() => console.log('PostgreSQL connected ✅'))
  .catch((err) => console.error('DB error ❌', err));

/* ================= JWT ================= */

const JWT_SECRET = process.env.JWT_SECRET;

const generateToken = (firebase_uid) => {
  return jwt.sign({ firebase_uid }, JWT_SECRET, {
    expiresIn: '7d',
  });
};

/* ================= MIDDLEWARE ================= */

const verifyJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

/* ================= ROUTES ================= */

app.get('/', (req, res) => {
  res.send('Trendora API running...');
});

/* ---------- REGISTER USER ---------- */

app.post('/users', async (req, res) => {
  try {
    const {
      firebase_uid,
      first_name,
      last_name,
      email,
      phone,
      address,
      location,
      role,
    } = req.body;

    // ✅ Validation
    if (!firebase_uid) {
      return res.status(400).json({ error: 'firebase_uid required' });
    }

    // ✅ Check duplicate user
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE firebase_uid = $1',
      [firebase_uid]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // ✅ Insert user
    const result = await pool.query(
      `INSERT INTO users 
      (firebase_uid, first_name, last_name, email, phone, address, location, role)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING *`,
      [
        firebase_uid,
        first_name,
        last_name,
        email,
        phone || '',
        address || '',
        location || '',
        role || 'user',
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------- LOGIN ---------- */

app.post('/auth/login', async (req, res) => {
  try {
    const { firebase_uid } = req.body;

    if (!firebase_uid) {
      return res.status(400).json({ error: 'firebase_uid required' });
    }

    const result = await pool.query(
      'SELECT * FROM users WHERE firebase_uid = $1',
      [firebase_uid]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const token = generateToken(firebase_uid);

    res.json({
      message: 'Login successful',
      token,
      user,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------- PROFILE ---------- */

app.get('/profile', verifyJWT, async (req, res) => {
  try {
    const firebase_uid = req.user.firebase_uid;

    const result = await pool.query(
      'SELECT * FROM users WHERE firebase_uid = $1',
      [firebase_uid]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------- ADMIN MIDDLEWARE ---------- */

const verifyAdmin = async (req, res, next) => {
  try {
    const firebase_uid = req.user.firebase_uid;

    const result = await pool.query(
      'SELECT role FROM users WHERE firebase_uid = $1',
      [firebase_uid]
    );

    const user = result.rows[0];

    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }

    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/* ---------- ADMIN ROUTE ---------- */

app.get('/admin', verifyJWT, verifyAdmin, (req, res) => {
  res.json({ message: 'Welcome Admin 👑' });
});

/* ---------- PRODUCTS ---------- */

app.get('/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/products/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT * FROM products WHERE id = $1',
      [id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ================= START ================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});