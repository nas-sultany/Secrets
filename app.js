require("dotenv").config();
const express = require("express");
const bodyParser = require("body-Parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// initialize session settings
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);

// initialize and use passport to manage sessions
app.use(passport.initialize());
app.use(passport.session());

mongoose.set("useUnifiedTopology", true);
mongoose.set("useCreateIndex", true);
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  // must be mongoose schema to make use of a plugin
  email: String,
  password: String,
});

// Use to hash, salt pws, and save users to db
// Use passport local mongoose as plugin
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

// create local login strategy
passport.use(User.createStrategy());

// serialize and deserialize user
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  // use passport to logout user
  req.logout();
  res.redirect("/");
});

app.post("/register", function (req, res) {
  // passport local mongoose used as middleman instead of creating user and then saving
  User.register({ username: req.body.username }, req.body.password, function (
    err,
    user
  ) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  // passport login method
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function () {
  console.log("Server started on port 3000.");
});
