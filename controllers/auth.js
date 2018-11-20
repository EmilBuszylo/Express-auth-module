const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const passport = require('passport');
var nodemailer = require('nodemailer');
var crypto = require('crypto');
const config = require('./config');

const User = require("../models/user");

async function generateToken() {
    const buffer = await new Promise((resolve, reject) => {
      crypto.randomBytes(256, function(ex, buffer) {
        if (ex) {
          reject("error generating token");
        }
        resolve(buffer);
      });
    });
    const token = crypto
      .createHash("sha1")
      .update(buffer)
      .digest("hex");

    return token;
}

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

exports.forgotPassword = async (req, res, done) => {

    try {
        const existingUser = await User.findOne({'email': req.body.email});

        if (!existingUser) {
            return res.status(404).json({
                message: "Mail not found"
            });
        }

        const token =  await generateToken();

        if(token) {
            existingUser.resetPasswordToken = token;
            existingUser.resetPasswordExpires = Date.now() + 3600000;

            const user = await existingUser.save();

            if(user) {
                const smtpTransport = nodemailer.createTransport({
                    service:'Gmail',
                    auth: {
                      user: config.APP_EMAIL,
                      pass: config.APP_EMAIL_PASSWORD
                    }
                  });

                const mailOptions = {
                    to: user.email,
                    from: config.APP_EMAIL,
                    subject: 'Node.js Password Reset',
                    text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                      'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                      'http://' + req.body.host + '/reset-password/' + token + '\n\n' +
                      'If you did not request this, please ignore this email and your password will remain unchanged.\n'
                };

                smtpTransport.sendMail(mailOptions, function(err) {

                    if(err) {
                        return res.status(404).json({
                            message: "Reset password link hasn't been sent",
                            sent: false
                        });
                    }

                    res.status(200).json({
                        message: "Reset password link has been sent",
                        sent: true
                    });
                    return done(err, 'done');
                });
            }
        }
    } catch (error) {
        return done(error);
    }

}

exports.resetPassword = async (req, res, next) => {

    try {
        const existingUser = await User.findOne({'resetPasswordToken': req.params.token, resetPasswordExpires: {$gt: Date.now()}});

        if (existingUser) {

            if(req.body.newPassword === req.body.confirmPassword) {

                const userPassword = await bcrypt.hash(req.body.newPassword, 10);

                if (userPassword) {

                    existingUser.password = userPassword;
                    existingUser.name = 'test';
                    existingUser.resetPasswordToken = undefined;
                    existingUser.resetPasswordExpires = undefined;

                    const user = await existingUser.save();

                    if (user) {
                        const token = jwt.sign({ id: user._id }, 'top_secret', {
                            expiresIn: 246400
                        });

                        // return new token for auto sign in after password reset
                        return res.status(200).json({ auth: true, token: token });
                    } else {
                        return res.status(422).send({
                            message: "Unprocessable Entity",
                            status: 'Unprocessable'
                        });
                    }
                }

            } else {
                return res.status(422).send({
                    message: 'Passwords do not match',
                    status: ' not match'
                });
            }

        } else {
            return res.status(400).json({
                message: "Password reset token is invalid or has expired.",
                status: 'invalid'
            });
        }

    } catch (error) {

    }
}
