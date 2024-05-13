const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql")
const multer = require("multer");
const bcrypt = require("bcryptjs");
const fs = require("fs");

require('dotenv').config();


app = express();
app.use(express.json());

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});


db.connect(err => {
    if(err) throw err;
    console.log("Database connection successfull!")
});

const storage = multer.diskStorage({
    destination : (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage: storage});

app.get('/', function (req, res){
    res.send("Hey this is the beginning part!")
});

// Middleware for authenticating tokens
function authenticateToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1]; // Bearer TOKEN
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Failed to authenticate token' });
        }

        req.user = decoded;
        next();
    });
}

app.post('/signup', upload.single('image'), function(req, res){
    const { name, phone, age, city, email, password, role_id } = req.body;
    console.log("Received data:", req.body);

    if (!password) {
        console.error("Password is missing!");
        return res.status(400).json({ error: 'Password is required' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.error("Error hashing password:", err);
            return res.status(500).json({ error: 'Password not hashed' });
        }
        console.log("Hashed password:", hash);
        
        // Read the file into a buffer
        let imgBuffer = null;
        if (req.file) {
            imgBuffer = fs.readFileSync(req.file.path);
        }
        
        const query = 'INSERT INTO users (name, phone, age, city, email, image_blob, password, role_id) VALUES (?,?,?,?,?,?,?,?)';
        db.query(query, [name, phone, age, city, email, imgBuffer, hash, role_id], (err, result) => {
            if (err) {
                console.error("Database error:", err.message);
                return res.status(500).json({ error: err.message });
            }
            res.status(201).send('User registered');
        });
    });
});


app.post('/login', function(req, res){
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (results.length === 0) {
            return res.status(404).send('User not found.');
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.status(500).json({ error: 'Error checking password' });
            }
            if (!isMatch) {
                return res.status(401).send('Password incorrect');
            }

            const token = jwt.sign({ id: user.id, role_id: user.role_id }, process.env.JWT_SECRET, { expiresIn: '24h' });
            res.json({ token });
            console.log("Token:", token);
        });
    });
});



function checkRole(requiredRoles) {
    return function(req, res, next) {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(401).json({ error: 'Failed to authenticate token' });
            }

            req.user = decoded;
            console.log('Decoded role_id:', req.user.role_id); // Check the decoded role ID
            console.log('Required roles:', requiredRoles); // Check required roles being checked

            // Convert both to strings or numbers to ensure correct comparison
            if (!requiredRoles.includes(String(req.user.role_id))) {
                return res.status(403).json({ error: 'You do not have permission to perform this action' });
            }

            next();
        });
    };
}


//  ['superuser', 'principal', 'teacher', 'student']= ['1', '2', '3', '4']

// Route to create users
app.post('/create-user', upload.single('image'),authenticateToken, checkRole(['1', '2', '3', '4']), function(req, res) {
    // Extract the role from the body to determine what roles this user can create
    const { name, phone, age, city, email, password, role_id, intendedRoleId } = req.body;
    const creatorRole = req.user.role_id;
    console.log(creatorRole);
    const allowedRoles = {
        '1': ['2', '3', '4'],
        '2': ['3', '4'],
        '3': ['4']
    };

    if (!allowedRoles[creatorRole].includes(intendedRoleId)) {
        return res.status(403).json({ error: 'You do not have permission to create this role' });
    }

    // Check required fields
    if (!name || !phone || !age || !city || !email || !password || !role_id || !intendedRoleId) {
        return res.status(400).json({ error: 'All fields are required' });
    }

     // Hash the password
     bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Error hashing password' });
        }

        // Read the file into a buffer
        let imgBuffer = null;
        if (req.file) {
            imgBuffer = fs.readFileSync(req.file.path);
        }

        // Insert the new user into the database
        const query = 'INSERT INTO users (name, phone, age, city, email, image_blob, password, role_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        db.query(query, [name, phone, age, city, email, imgBuffer, hash, intendedRoleId], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Database error: ' + err.message });
            }
            res.status(201).json({ message: 'User created successfully' });
        });
    });
});


// Route for a teacher to create a class
app.post('/create-class', checkRole(['teacher']), function(req, res) {
    const { className, teacherId } = req.body;
    if (req.user.id !== teacherId) {
        return res.status(403).json({ error: 'You can only create classes for yourself' });
    }

    // Insert class into the database
    const query = 'INSERT INTO classes (name, teacher_id) VALUES (?, ?)';
    db.query(query, [className, teacherId], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Database error creating class' });
        }
        res.status(201).send('Class created successfully');
    });

});


const port = 8081
app.listen(port, () =>{
    console.log("Server started on port 8081")
})