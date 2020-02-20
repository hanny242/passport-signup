const express = require("express");
const router = express.Router();
const passport = require("passport");
const ensureLogin = require("connect-ensure-login");

// Require the User model
const User = require("../models/Users");

// Bcrypt to encrypt passwords
var bcrypt = require('bcryptjs');
const bcryptSalt = 10;

router.get("/signup", (req, res, next) => {
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
          res.redirect("/");
        }
      });
    })
    .catch(error => {
      next(error);
    });
});

//login

router.get("/login", (req, res, next) => {
    res.render("login", { "message": req.flash("error") });
  });

router.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
    passReqToCallback: true
  })
);

router.get("/profile-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("profile-page", { user: req.user });
});

//logout

router.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/login");
  });

module.exports = router;
