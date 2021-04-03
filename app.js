const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const bcrypt = require('bcryptjs'); 

const indexRouter = require('./routes/index'); 

const mongoDb = "mongodb+srv://jay_patel:Jay@1234@cluster0.e7ok8.mongodb.net/authentication_project?retryWrites=true&w=majority";
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) { 
        return done(err);
      };
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      if(bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user)
        } else {
          // passwords do not match!
          return done(null, false, { message: "Incorrect password" })
        }
      }))
      return done(null, user);
    });
  })
);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


///use local variable anywhere in app
app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", (req, res) => res.render("index", {user: req.user}));

//POST login
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);

// LOGOUT
app.get("/log-out", (req, res) => {
  req.logout();
  res.redirect("/");
});

//GET signup
app.get("/sign-up", (req, res) => res.render("sign-up-form"));

//POST signup
app.post("/sign-up", (req, res, next) => {
  
  bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
    if(err) {return next(err); }

    // otherwise, store hashedPassword in DB
    const user = new User({
      username: req.body.username,
      password: hashedPassword
    });
      
    user.save(err => {
      if (err) { return next(err); };
      res.redirect("/");
    });
  });

});

app.listen(3000, () => console.log("app listening on port 3000!")); 