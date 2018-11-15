const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require('passport');

const User = require("../models/user");

exports.signup = (req, res, next) => {
    User.find({ 'email': req.body.email })
        .then(user => {
            if (user.length >= 1) {
                return res.status(409).json({
                    message: "Mail exists"
                });
            } else {
                bcrypt.hash(req.body.password, 10, (err, hash) => {
                    if (err) {
                        return res.status(500).json({
                            error: err
                        });
                    } else {
                        const user = new User({
                            _id: new mongoose.Types.ObjectId(),
                            email: req.body.email,
                            password: hash
                        });

                        user
                            .save()
                            .then(result => {
                                return res.status(201).json({
                                    message: "User created"
                                });
                            })
                            .catch(err => {
                                console.log(err);
                                return res.status(500).json({
                                    error: err
                                });
                            });
                    }
                });
            }
        });
};

exports.login = (req, res, next) => {
    passport.authenticate('local', async (err, user, info) => {
        try {
            if (err || !user) {
                const error = new Error('An Error occured')
                return res.status(500).json({
                    error: err
                });
            }
            req.login(user, { session: false }, async (error) => {
                if (error) return next(error)

                const token = jwt.sign({ id: user._id }, 'top_secret', {
                    expiresIn: 246400
                });

                return res.status(200).json({ auth: true, token: token });
            });
        } catch (error) {
            return next(error);
        }
    })(req, res, next);
};

exports.logout = (req, res) => {
    req.logout();
    res.redirect('/');
};
