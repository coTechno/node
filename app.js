const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("./models/User");
const clc = require("cli-color");

const app = express();
const PORT = 8000;
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: "Zehra Khan Module Test : Node",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);
mongoose.set("strictQuery", true);
mongoose.connect(
  "mongodb+srv://zehraamirkhan:amir7017@cluster0.gjbhpfr.mongodb.net/moduletest",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
  console.log(clc.green("Connected to the Database"));
});

const JWT_SECRET = "myjwtsecret";
const authenticateUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect("/login");
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.session.userId = decoded.userId;
    next();
  } catch (error) {
    console.error(error);
    res.redirect("/login");
  }
};

app.set("view engine", "ejs");

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, email, password, phonenumber } = req.body;
  try {
    const user = await User.create({ username, email, password, phonenumber });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1d",
    });
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/dashboard");
  } catch (error) {
    console.error(error);
    res.render("register", { error: "Error creating user" });
  }
});

app.get("/login", function (req, res) {
  const options = { async: true };
  res.render("login", { error: null }, options);
});

app.post("/login", async (req, res) => {
  const { email, password, phonenumber } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render("login", { error: "Invalid email or password" });
    }
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.render("login", { error: "Invalid email or password" });
    }
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1d",
    });
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/dashboard");
  } catch (error) {
    const options = { async: true };
    res.render("login", { error: error }, options);
  }
});

app.get("/dashboard", authenticateUser, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    res.render("dashboard", { user });
  } catch (error) {
    console.error(error);
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  req.session.destroy();
  res.redirect("/");
});

// Verify user email
app.get("/verify/:token", async (req, res) => {
  const { token } = req.params;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.render("verify", { message: "User not found" });
    }
    if (user.isVerified) {
      return res.render("verify", { message: "User already verified" });
    }
    user.isVerified = true;
    await user.save();
    res.render("verify", { message: "Email verified successfully" });
  } catch (error) {
    console.error(error);
    res.render("verify", { message: "Invalid token" });
  }
});
app.listen(PORT, () => {
  console.log(clc.yellow("App is running at "));
  console.log(clc.blue.underline(`http://localhost:${PORT}`));
});
