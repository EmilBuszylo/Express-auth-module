const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const mongoose = require('mongoose');
const config = require('../config');
const bcrypt = require("bcrypt");

const User = require("../models/user");

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id)
        .then(user => {
            done(null, user)
        })
});

passport.use(
    new GoogleStrategy({
        clientID: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        callbackURL: '/auth/google/callback',
        proxy: true
    },
        async (accesToken, refreshToken, profile, done) => {

            try {
                const existingUser = await User.findOne({ 'email': profile.emails[0].value });

                if (existingUser) {
                    done(null, existingUser);
                } else {
                    const user = await new User(
                        {
                            _id: new mongoose.Types.ObjectId(),
                            email: profile.emails[0].value,
                            profile: {
                                name: profile.displayName,
                            }
                        }
                    ).save()
                    done(null, user);
                }

            } catch (error) {
                return done(error);
            }
        }
    )
);

passport.use(
    new FacebookStrategy({
        clientID: config.FACEBOOK_APP_ID,
        clientSecret: config.FACEBOOK_APP_SECRET,
        callbackURL: "/auth/facebook/callback",
        profileFields: ['id', 'email', 'displayName'],
        proxy: true
    },
        async (accessToken, refreshToken, profile, done) => {

            try {
                const existingUser = await User.findOne({ 'email': profile.emails[0].value });

                if (existingUser) {
                    done(null, existingUser);
                } else {
                    const user = await new User(
                        {
                            _id: new mongoose.Types.ObjectId(),
                            email: profile.emails[0].value,
                            profile: {
                                name: profile.displayName,
                            }
                        }
                    ).save()
                    done(null, user);
                }

            } catch (error) {
                return done(error);
            }
        }
    ));

passport.use(
    new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        proxy: true
    },
    async (username, password, done) => {

        try {
            const existingUser = await User.findOne({ 'email': username });

            if(!existingUser) {
                return done(null, false);
            }

            bcrypt.compare(password, existingUser.password, (err, result) => {
                if (err) {
                    return res.status(401).json({
                        message: "Auth failed"
                    });
                }
                if (result) {
                    return done(null, existingUser);
                }
                done(null, false, { message: "Invalid password" });
            });

        } catch (error) {
            return done(error);
        }

    }





    // function (username, password, done) {
    //     User.findOne({ 'email': username }, function (err, user) {
    //         if (err) { return done(err); }
    //         if (!user) { return done(null, false); }
    //         bcrypt.compare(password, user.password, (err, result) => {
    //             if (err) {
    //                 return res.status(401).json({
    //                     message: "Auth failed"
    //                 });
    //             }
    //             if (result) {
    //                 return done(null, user);
    //             }
    //             done(null, false, { message: "Invalid password" });
    //         });
    //     });
    // }
));
