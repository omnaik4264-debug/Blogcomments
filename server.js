const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cors());

// Connect MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/blogDB');

// User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

// Post Schema
const PostSchema = new mongoose.Schema({
    title: String,
    content: String,
    author: String,
    comments: [{ author: String, text: String, created: { type: Date, default: Date.now } }]
}, { timestamps: true });
const Post = mongoose.model('Post', PostSchema);

// Auth Middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        req.user = jwt.verify(token, 'SECRET_KEY');
        next();
    } catch {
        res.status(403).json({ error: 'Invalid token' });
    }
};

// Authentication Endpoints
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = await User.create({ username, password: hashedPassword });
        res.status(201).json({ message: 'User created' });
    } catch (err) {
        res.status(400).json({ error: 'Username taken' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, 'SECRET_KEY');
        return res.json({ token, username: user.username });
    }
    res.status(400).json({ error: 'Invalid credentials' });
});

// RESTful Post Endpoints
app.get('/api/posts', async (req, res) => {
    const posts = await Post.find().sort({ createdAt: -1 });
    res.json(posts);
});

app.post('/api/posts', authenticate, async (req, res) => {
    const post = await Post.create({ ...req.body, author: req.user.username });
    res.status(201).json(post);
});

app.put('/api/posts/:id', authenticate, async (req, res) => {
    const post = await Post.findById(req.params.id);
    if (post.author !== req.user.username) return res.status(403).json({ error: 'Forbidden' });
    Object.assign(post, req.body);
    await post.save();
    res.json(post);
});

app.delete('/api/posts/:id', authenticate, async (req, res) => {
    const post = await Post.findById(req.params.id);
    if (post.author !== req.user.username) return res.status(403).json({ error: 'Forbidden' });
    await post.deleteOne();
    res.json({ message: 'Deleted' });
});

app.post('/api/posts/:id/comments', authenticate, async (req, res) => {
    const post = await Post.findById(req.params.id);
    post.comments.push({ author: req.user.username, text: req.body.text });
    await post.save();
    res.json(post);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));