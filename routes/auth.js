const express = require("express");
const router = express.Router();
const passport = require("passport");
const ensureLogin = require("connect-ensure-login");
const LocalStrategy = require("passport-local").Strategy;
const flash = require("connect-flash");

// Require the User model
const User = require("../models/Users");

// Bcrypt to encrypt passwords
var bcrypt = require('bcryptjs');
const bcryptSalt = 10;

router.get("/signup", (req, res, next) => {
    debugger;
  res.render("signup");
});

router.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username === "" || password === "") {
    res.render("signup", { message: "Indicate username and password" });
    return;
  }

  User.findOne({ username })
    .then(user => {
      if (user !== null) {
        res.render("signup", { message: "The username already exists" });
        return;
      }

      const salt = bcrypt.genSaltSync(bcryptSalt);
      const hashPass = bcrypt.hashSync(password, salt);

      const newUser = new User({
        username,
        password: hashPass
      });

      newUser.save(err => {
        if (err) {
          res.render("signup", { message: "Something went wrong" });
        } else {
          res.redirect("/login");
        }
      });
    })
    .catch(error => {
      next(error);
    });
});

//login

router.get("/login", (req, res, next) => {
    res.render("login");
  });

router.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/profile-page",
    failureRedirect: "/login",
    failureFlash: true,
    passReqToCallback: true
  })
);

router.get("/profile-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("profile-page", { user: req.user });
});

passport.serializeUser((user, cb) => {
    cb(null, user._id);
  });
  
  passport.deserializeUser((id, cb) => {
    User.findById(id, (err, user) => {
      if (err) { return cb(err); }
      cb(null, user);
    });
  });
  
  passport.use(new LocalStrategy((username, password, next) => {
    User.findOne({ username }, (err, user) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        return next(null, false, { message: "Foute gebruikersnaam of wachtwoord" });
      }
      if (!bcrypt.compareSync(password, user.password)) {
        return next(null, false, { message: "Foute gebruikersnaam of wachtwoord" });
      }
  
      return next(null, user);
    });
  }));

//logout

router.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/login");
  });

module.exports = router;
