const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// ===== CONFIG =====
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing in environment variables");
  process.exit(1);
}

if (!MONGO_URI) {
  console.error("MONGO_URI is missing in environment variables");
  process.exit(1);
}

// ===== MongoDB Connection =====
mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// ===== Schemas =====

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);

const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  completed: { type: Boolean, default: false },
  userId: { type: String, required: true }
});

const Task = mongoose.model("Task", taskSchema);

// ===== Root Route =====
app.get("/", (req, res) => {
  res.send("Backend is running.");
});

// ===== Auth Middleware =====
function auth(req, res, next) {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.userId = verified.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ===== Auth Routes =====

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();
    res.json({ message: "User created successfully" });
  } catch {
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.json({ token });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

// ===== Task Routes =====

app.post("/tasks", auth, async (req, res) => {
  try {
    const { title } = req.body;
    if (!title) return res.status(400).json({ error: "Title required" });

    const newTask = new Task({
      title,
      userId: req.userId
    });

    await newTask.save();
    res.status(201).json(newTask);
  } catch {
    res.status(500).json({ error: "Could not create task" });
  }
});

app.get("/tasks", auth, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.userId });
    res.json(tasks);
  } catch {
    res.status(500).json({ error: "Could not fetch tasks" });
  }
});

app.put("/tasks/:id", auth, async (req, res) => {
  try {
    const { title, completed } = req.body;

    const task = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { title, completed },
      { new: true }
    );

    if (!task) return res.status(404).json({ error: "Task not found" });

    res.json(task);
  } catch {
    res.status(500).json({ error: "Could not update task" });
  }
});

app.delete("/tasks/:id", auth, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete(
      { _id: req.params.id, userId: req.userId }
    );

    if (!task) return res.status(404).json({ error: "Task not found" });

    res.json({ message: "Task deleted" });
  } catch {
    res.status(500).json({ error: "Could not delete task" });
  }
});

// ===== Server =====
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
