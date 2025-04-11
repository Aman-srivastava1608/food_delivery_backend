require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ✅ PostgreSQL connection pool
const db = new Pool({
  host: process.env.PGHOST,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  port: process.env.PGPORT,
  ssl: { rejectUnauthorized: false }
});

// ✅ Register endpoint
app.post('/register', async (req, res) => {
  const { full_name, email, phone, address, password, confirm_password } = req.body;

  if (!full_name || !email || !phone || !address || !password || !confirm_password) {
    return res.status(400).send('Please fill in all fields');
  }

  if (password !== confirm_password) {
    return res.status(400).send('Passwords do not match');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO users2 (full_name, email, phone, address, password) VALUES ($1, $2, $3, $4, $5)`;
    await db.query(query, [full_name, email, phone, address, hashedPassword]);
    res.send('User registered successfully');
  } catch (err) {
    console.error("❌ Registration Error:", err);
    res.status(500).send('Error in registration');
  }
});

// ✅ Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await db.query(`SELECT * FROM users2 WHERE email = $1`, [email]);
    const user = result.rows[0];

    if (!user) return res.status(401).send('Invalid email or password');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).send('Invalid email or password');

    res.json({ message: 'Login successful', name: user.full_name });
  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).send('Server error');
  }
});

// ✅ Start server
// ✅ Root route for Render test
app.get('/', (req, res) => {
  res.send('🚀 Food Delivery Backend is Running!');
});

// ✅ Start server
app.listen(process.env.PORT || 3000, () => {
  console.log(`🚀 Server running on port ${process.env.PORT || 3000}`);
});
