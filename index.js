const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// ===== CONFIG =====
const JWT_SECRET =  process.env.JWT_SECRET ;

// ===== MongoDB Connection =====
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log(err));

// ===== Schemas =====

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});

const User = mongoose.model("User", userSchema);

// Task Schema
const taskSchema = new mongoose.Schema({
  title: String,
  completed: Boolean,
  userId: String
});

const Task = mongoose.model("Task", taskSchema);

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

// Signup
app.post("/signup", async (req, res) => {
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
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ userId: user._id }, JWT_SECRET);

  res.json({ token });
});

// ===== Task Routes (Protected) =====

// Create Task
app.post("/tasks", auth, async (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ error: "Title required" });

  const newTask = new Task({
    title,
    completed: false,
    userId: req.userId
  });

  await newTask.save();
  res.status(201).json(newTask);
});

// Get User's Tasks
app.get("/tasks", auth, async (req, res) => {
  const tasks = await Task.find({ userId: req.userId });
  res.json(tasks);
});

// Update Task
app.put("/tasks/:id", auth, async (req, res) => {
  const { title, completed } = req.body;

  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.userId },
    { title, completed },
    { new: true }
  );

  if (!task) return res.status(404).json({ error: "Task not found" });

  res.json(task);
});

// Delete Task
app.delete("/tasks/:id", auth, async (req, res) => {
  const task = await Task.findOneAndDelete(
    { _id: req.params.id, userId: req.userId }
  );

  if (!task) return res.status(404).json({ error: "Task not found" });

  res.json({ message: "Task deleted" });
});

// ===== Server =====
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
