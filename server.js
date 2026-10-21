const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const JWT_SECRET = process.env.JWT_SECRET;

// ---------- Models ----------
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["company", "applicant"], required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", userSchema);

// ---------- Helpers ----------
function makeToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}

function publicUser(user) {
  return { id: user._id, name: user.name, email: user.email, role: user.role };
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Please log in" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "Session expired. Please log in again" });
  }
}

// ---------- Routes ----------
app.get("/", function (req, res) {
  res.json({ message: "JobBoard API is running" });
});

app.get("/health", function (req, res) {
  const states = ["disconnected", "connected", "connecting", "disconnecting"];
  res.json({ api: "ok", database: states[mongoose.connection.readyState] });
});

app.post("/api/signup", async function (req, res) {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const role = req.body.role === "company" ? "company" : "applicant";

    if (!name) return res.status(400).json({ error: "Name is required" });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Enter a valid email" });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    const exists = await User.findOne({ email: email });
    if (exists) return res.status(400).json({ error: "This email is already registered" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name: name, email: email, password: hash, role: role });
    res.json({ token: makeToken(user), user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.post("/api/login", async function (req, res) {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = await User.findOne({ email: email });
    if (!user) return res.status(400).json({ error: "Wrong email or password" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Wrong email or password" });
    res.json({ token: makeToken(user), user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.get("/api/me", auth, async function (req, res) {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(401).json({ error: "Account not found" });
  res.json({ user: publicUser(user) });
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) console.error("MONGODB_URI is not set");
if (!JWT_SECRET) console.error("JWT_SECRET is not set");

if (MONGODB_URI) {
  mongoose
    .connect(MONGODB_URI)
    .then(function () { console.log("MongoDB connected"); })
    .catch(function (err) { console.error("MongoDB error:", err.message); });
}

app.listen(PORT, function () {
  console.log("Server running on port " + PORT);
});
