const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');

const bcrypt = require('bcrypt');

const app = express();
const PORT = 4000;

// Create SQLite database connection
const db = new sqlite3.Database('./database.db');

// Create users table
db.serialize(() => {
  db.run(
    'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, firstName TEXT, lastName TEXT, email TEXT, phoneNumber TEXT, password TEXT, dob TEXT, address TEXT)'
  );
});

// Configure body-parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors({
  origin: '*'
}));
app.use(bodyParser.json());

// Login API
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find user with the provided email
  db.get('SELECT * FROM users WHERE email = ?', email, (err, row) => {
    if (err) {
      console.error(err.message);
      res.header('Access-Control-Allow-Origin', '*');
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!row) {
      res.header('Access-Control-Allow-Origin', '*');
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare the provided password with the stored hashed password
    bcrypt.compare(password, row.password, (bcryptErr, result) => {
      if (bcryptErr) {
        console.error(bcryptErr.message);
        res.header('Access-Control-Allow-Origin', '*');
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!result) {
        res.header('Access-Control-Allow-Origin', '*');
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Authentication successful
      res.json({ message: 'Login successful' });
    });
  });
});

// Registration API
app.post('/register', (req, res) => {
  const { firstName, lastName, email, phoneNumber, password, confirmPassword, dob, address } = req.body;

  // Check if password and confirm password match
  if (password !== confirmPassword) {
        res.header('Access-Control-Allow-Origin', '*');

    return res.status(400).json({ error: 'Password and confirm password do not match' });
  }

  // Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error(err.message);
          res.header('Access-Control-Allow-Origin', '*');

      return res.status(500).json({ error: 'Internal server error' });
    }

    // Insert new user into the database
    db.run(
      'INSERT INTO users (firstName, lastName, email, phoneNumber, password, dob, address) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [firstName, lastName, email, phoneNumber, hashedPassword, dob, address],
      (dbErr) => {
        if (dbErr) {
          console.error(dbErr.message);
              res.header('Access-Control-Allow-Origin', '*');

          return res.status(500).json({ error: 'Internal server error' });
        }

        res.json({ message: 'Registration successful' });
      }
    );
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Fetch all users API
app.get('/users', (req, res) => {
  db.all('SELECT * FROM users', (err, rows) => {
    if (err) {
      res.header('Access-Control-Allow-Origin', '*');

      console.error(err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.header('Access-Control-Allow-Origin', '*');

    res.json({ users: rows });
  });
});
