const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const db = new Database('lapiehub.db');
const JWT_SECRET = process.env.JWT_SECRET || 'lapiehub_secret_2026';
const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════
// DATABASE INIT
// ═══════════════════════════════════════
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT UNIQUE NOT NULL,
    classe TEXT,
    solde TEXT,
    grade TEXT,
    pass_lapia TEXT,
    assurance TEXT,
    avatar TEXT DEFAULT '🐦',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    image_url TEXT,
    likes INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_nom TEXT NOT NULL,
    UNIQUE(post_id, user_nom)
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS follows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower TEXT NOT NULL,
    following TEXT NOT NULL,
    UNIQUE(follower, following)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_nom TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ═══════════════════════════════════════
// MIDDLEWARE AUTH
// ═══════════════════════════════════════
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

function adminMiddleware(req, res, next) {
  const admins = ['Maxime SANCHIS', 'Maël FRIDEL'];
  if (!admins.includes(req.user?.nom)) return res.status(403).json({ error: 'Accès refusé' });
  next();
}

// ═══════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════
app.post('/api/login', async (req, res) => {
  const { nom, password } = req.body;
  if (!nom || !password) return res.status(400).json({ error: 'Champs manquants' });
  try {
    const url = `${APPS_SCRIPT_URL}?action=login&username=${encodeURIComponent(nom)}&password=${encodeURIComponent(password)}`;
    const response = await fetch(url);
    const data = await response.json();
    if (!data.success) return res.status(401).json({ error: data.message || 'Identifiants incorrects' });
    // Upsert user
    db.prepare(`INSERT INTO users (nom, classe, solde, grade, pass_lapia, assurance)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(nom) DO UPDATE SET classe=excluded.classe, solde=excluded.solde, grade=excluded.grade`
    ).run(data.nom, data.classe, String(data.solde), data.grade, data.pass_lapia, data.assurance);
    const token = jwt.sign({ nom: data.nom }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, user: data });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ═══════════════════════════════════════
// USER ROUTES
// ═══════════════════════════════════════
app.get('/api/users', authMiddleware, (req, res) => {
  const users = db.prepare('SELECT nom, classe, grade, avatar FROM users').all();
  res.json(users);
});

app.get('/api/users/:nom', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE nom = ?').get(req.params.nom);
  if (!user) return res.status(404).json({ error: 'Membre introuvable' });
  const posts = db.prepare('SELECT * FROM posts WHERE author = ? ORDER BY created_at DESC').all(req.params.nom);
  const followers = db.prepare('SELECT COUNT(*) as count FROM follows WHERE following = ?').get(req.params.nom).count;
  const following = db.prepare('SELECT COUNT(*) as count FROM follows WHERE follower = ?').get(req.params.nom).count;
  res.json({ ...user, posts, followers, following });
});

app.put('/api/users/avatar', authMiddleware, (req, res) => {
  const { avatar } = req.body;
  db.prepare('UPDATE users SET avatar = ? WHERE nom = ?').run(avatar, req.user.nom);
  res.json({ success: true });
});

// ═══════════════════════════════════════
// POSTS ROUTES
// ═══════════════════════════════════════
app.get('/api/posts', authMiddleware, (req, res) => {
  const posts = db.prepare(`
    SELECT p.*, u.avatar, u.grade,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as likes,
      (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count,
      (SELECT COUNT(*) FROM likes WHERE post_id = p.id AND user_nom = ?) as user_liked
    FROM posts p
    LEFT JOIN users u ON p.author = u.nom
    ORDER BY p.created_at DESC
    LIMIT 50
  `).all(req.user.nom);
  res.json(posts);
});

app.post('/api/posts', authMiddleware, (req, res) => {
  const { content } = req.body;
  if (!content || content.length > 500) return res.status(400).json({ error: 'Contenu invalide' });
  const result = db.prepare('INSERT INTO posts (author, content) VALUES (?, ?)').run(req.user.nom, content);
  res.json({ success: true, id: result.lastInsertRowid });
});

app.delete('/api/posts/:id', authMiddleware, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post introuvable' });
  const admins = ['Maxime SANCHIS', 'Maël FRIDEL'];
  if (post.author !== req.user.nom && !admins.includes(req.user.nom)) return res.status(403).json({ error: 'Accès refusé' });
  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ═══════════════════════════════════════
// LIKES ROUTES
// ═══════════════════════════════════════
app.post('/api/posts/:id/like', authMiddleware, (req, res) => {
  try {
    db.prepare('INSERT INTO likes (post_id, user_nom) VALUES (?, ?)').run(req.params.id, req.user.nom);
    const post = db.prepare('SELECT author FROM posts WHERE id = ?').get(req.params.id);
    if (post && post.author !== req.user.nom) {
      db.prepare('INSERT INTO notifications (user_nom, type, content) VALUES (?, ?, ?)').run(
        post.author, 'like', `${req.user.nom} a aimé ton post`
      );
    }
    res.json({ success: true, liked: true });
  } catch {
    db.prepare('DELETE FROM likes WHERE post_id = ? AND user_nom = ?').run(req.params.id, req.user.nom);
    res.json({ success: true, liked: false });
  }
});

// ═══════════════════════════════════════
// COMMENTS ROUTES
// ═══════════════════════════════════════
app.get('/api/posts/:id/comments', authMiddleware, (req, res) => {
  const comments = db.prepare(`
    SELECT c.*, u.avatar FROM comments c
    LEFT JOIN users u ON c.author = u.nom
    WHERE c.post_id = ? ORDER BY c.created_at ASC
  `).all(req.params.id);
  res.json(comments);
});

app.post('/api/posts/:id/comments', authMiddleware, (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Commentaire vide' });
  db.prepare('INSERT INTO comments (post_id, author, content) VALUES (?, ?, ?)').run(req.params.id, req.user.nom, content);
  const post = db.prepare('SELECT author FROM posts WHERE id = ?').get(req.params.id);
  if (post && post.author !== req.user.nom) {
    db.prepare('INSERT INTO notifications (user_nom, type, content) VALUES (?, ?, ?)').run(
      post.author, 'comment', `${req.user.nom} a commenté ton post`
    );
  }
  res.json({ success: true });
});

// ═══════════════════════════════════════
// FOLLOWS ROUTES
// ═══════════════════════════════════════
app.post('/api/follow/:nom', authMiddleware, (req, res) => {
  try {
    db.prepare('INSERT INTO follows (follower, following) VALUES (?, ?)').run(req.user.nom, req.params.nom);
    db.prepare('INSERT INTO notifications (user_nom, type, content) VALUES (?, ?, ?)').run(
      req.params.nom, 'follow', `${req.user.nom} te suit maintenant`
    );
    res.json({ success: true, following: true });
  } catch {
    db.prepare('DELETE FROM follows WHERE follower = ? AND following = ?').run(req.user.nom, req.params.nom);
    res.json({ success: true, following: false });
  }
});

// ═══════════════════════════════════════
// MESSAGES ROUTES
// ═══════════════════════════════════════
app.get('/api/messages/:nom', authMiddleware, (req, res) => {
  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
    ORDER BY created_at ASC
  `).all(req.user.nom, req.params.nom, req.params.nom, req.user.nom);
  res.json(messages);
});

app.post('/api/messages/:nom', authMiddleware, (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Message vide' });
  db.prepare('INSERT INTO messages (from_user, to_user, content) VALUES (?, ?, ?)').run(req.user.nom, req.params.nom, content);
  // Notif WebSocket
  broadcastToUser(req.params.nom, { type: 'message', from: req.user.nom, content });
  res.json({ success: true });
});

// ═══════════════════════════════════════
// NOTIFICATIONS ROUTES
// ═══════════════════════════════════════
app.get('/api/notifications', authMiddleware, (req, res) => {
  const notifs = db.prepare('SELECT * FROM notifications WHERE user_nom = ? ORDER BY created_at DESC LIMIT 20').all(req.user.nom);
  db.prepare('UPDATE notifications SET read = 1 WHERE user_nom = ?').run(req.user.nom);
  res.json(notifs);
});

app.get('/api/notifications/count', authMiddleware, (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_nom = ? AND read = 0').get(req.user.nom);
  res.json(count);
});

// ═══════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════
app.get('/api/admin/stats', authMiddleware, adminMiddleware, (req, res) => {
  const stats = {
    total_users: db.prepare('SELECT COUNT(*) as count FROM users').get().count,
    total_posts: db.prepare('SELECT COUNT(*) as count FROM posts').get().count,
    total_likes: db.prepare('SELECT COUNT(*) as count FROM likes').get().count,
    total_messages: db.prepare('SELECT COUNT(*) as count FROM messages').get().count,
  };
  res.json(stats);
});

app.get('/api/admin/posts', authMiddleware, adminMiddleware, (req, res) => {
  const posts = db.prepare('SELECT * FROM posts ORDER BY created_at DESC').all();
  res.json(posts);
});

// ═══════════════════════════════════════
// WEBSOCKET
// ═══════════════════════════════════════
const clients = new Map();

wss.on('connection', (ws, req) => {
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'auth') {
        const user = jwt.verify(data.token, JWT_SECRET);
        clients.set(user.nom, ws);
        ws.userNom = user.nom;
      }
    } catch {}
  });
  ws.on('close', () => {
    if (ws.userNom) clients.delete(ws.userNom);
  });
});

function broadcastToUser(nom, data) {
  const client = clients.get(nom);
  if (client && client.readyState === WebSocket.OPEN) {
    client.send(JSON.stringify(data));
  }
}

// ═══════════════════════════════════════
// SERVE FRONTEND
// ═══════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`LapieHUB Social — port ${PORT}`));
