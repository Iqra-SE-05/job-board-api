const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", function (req, res) {
  res.json({ message: "JobBoard API is running" });
});

app.get("/health", function (req, res) {
  const states = ["disconnected", "connected", "connecting", "disconnecting"];
  res.json({ api: "ok", database: states[mongoose.connection.readyState] });
});

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error("MONGODB_URI is not set");
} else {
  mongoose
    .connect(MONGODB_URI)
    .then(function () { console.log("MongoDB connected"); })
    .catch(function (err) { console.error("MongoDB error:", err.message); });
}

app.listen(PORT, function () {
  console.log("Server running on port " + PORT);
});
