const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)");
    db.run("CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT)");
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Endpoint para registrar usuarios
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
        if (err) return res.status(500).send(err.message);
        res.status(201).send({ id: this.lastID });
    });
});

// Endpoint para autenticar usuarios
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
        if (err) return res.status(500).send(err.message);
        if (!row || !(await bcrypt.compare(password, row.password))) {
            return res.status(401).send('Usuario o contraseña incorrectos.');
        }
        res.status(200).send({ id: row.id, username: row.username });
    });
});

// Endpoint para subir o actualizar posts
app.post('/posts', async (req, res) => {
    const { title, content } = req.body;

    db.run("INSERT INTO posts (title, content) VALUES (?, ?)", [title, content], function(err) {
        if (err) return res.status(500).send(err.message);
        res.status(201).send({ id: this.lastID });
    });
});

// Inicio del servidor
app.listen(3000, () => {
    console.log('Servidor en funcionamiento en http://localhost:3000');
});
