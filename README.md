# Express-auth-module

## About

Express.js REST authorization app supported by MongoDB (I'm going to add MySql version in future) contains:

-   Signing up users to service with google, facebook (passport.js) and local by pass email and password.
-   If users signed up to service with local options and then want to use google, facbook login they are logged in on the created by local account (if email email provided during registration is the same as social media email).
-   Passwords are hashed with bcrypt.
-   If you'r loging to serwis by local you get json web token in response.
-   If you'r loging to serwis by social media you are redirect to login page and json web token has been saved in cookies.
-   Routes protect by verifyToken middleware. You have to send token by as request header 'x-access-token' with 'Bearer ' prefix.

## Initial setup

- `cd server`
- `yarn` or `npm install`, yarn is prefered option.
- Work with develop env
    -   `cd config` and `touch dev.js` in dev js add your configuration.
-   Work with production
    -   `touch env`, set NODE_ENV as 'production' and add your configuation.

## In plans

-   ~~add pass reminder by email~~,
-   add template for reset password email,
-   add simply example page,
-   add second version with MySql instead MongoDB.
