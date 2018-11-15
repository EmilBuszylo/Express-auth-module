const express = require("express");
const router = express.Router();
const passport = require('passport');
const jwt = require("jsonwebtoken");

const AuthContnroller = require('../controllers/auth');

router.post("/signup", AuthContnroller.signup);

router.post("/login", AuthContnroller.login);

router.post("/logout", AuthContnroller.logout);

const storeRedirectToInSession = (req, res, next) => {
    const redirectTo = req.headers.referer;
    req.session.redirectTo = redirectTo;
    next();
};

router.get(
    '/google',
    storeRedirectToInSession,
    passport.authenticate('google', {
        scope: ['profile', 'email']
    })
);

router.get(
    '/google/callback',
    passport.authenticate('google'),
    (req, res) => {
        const token = jwt.sign({ id: req.user._id }, 'top_secret');
        // Redirect to login page and set access token in cookies
        res.cookie('token', token);
        res.redirect(`${req.session.redirectTo}?token=${token}`);
    }
);

router.get(
    '/facebook',
    passport.authenticate('facebook', {
        scope: ['email']
    })
);

router.get(
    '/facebook/callback',
    passport.authenticate('facebook'),
    (req, res) => {
        const token = jwt.sign({ id: req.user._id }, 'top_secret');
        // Redirect to login page and set access token in cookies
        res.cookie('token', token);
        res.redirect(`${req.session.redirectTo}?token=${token}`);
    }
);

module.exports = router;
