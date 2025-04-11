const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MySQL DB Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'food_delivery'
});

db.connect(err => {
    if (err) throw err;
    console.log('✅ Database connected');
});

// Register API
app.post('/register', (req, res) => {
    const { full_name, email, phone, address, password, confirm_password } = req.body;

    if (!full_name || !email || !phone || !address || !password || !confirm_password) {
        return res.status(400).send('Please fill in all fields');
    }

    if (password !== confirm_password) {
        return res.status(400).send('Passwords do not match');
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const sql = `INSERT INTO users (full_name, email, phone, address, password) VALUES (?, ?, ?, ?, ?)`;

    db.query(sql, [full_name, email, phone, address, hashedPassword], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error in registration');
        }
        res.send('User registered successfully');
    });
});

// Login API
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server error');
        }

        if (results.length === 0) {
            return res.status(401).send('User not found');
        }

        const user = results[0];

        const isMatch = bcrypt.compareSync(password, user.password);
        if (!isMatch) {
            return res.status(401).send('Incorrect password');
        }

        res.send('Login successful');
    });
});

// Login API
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(401).send('Invalid email or password');

        const user = results[0];
        const isPasswordValid = bcrypt.compareSync(password, user.password);

        if (!isPasswordValid) return res.status(401).send('Invalid email or password');

        // Send back name and message
        res.json({ message: 'Login successful', name: user.name });
    });
});



// Start Server
app.listen(3000, () => {
    console.log('🚀 Server running at http://localhost:3000');
});
