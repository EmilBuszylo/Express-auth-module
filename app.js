const express = require("express");
const app = express();
const morgan = require("morgan");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const passport = require("passport");
const cookieSession = require("cookie-session");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const config = require('./config');

const authRoutes = require('./routes/auth');

require('dotenv').config();
require('./services/passport');

mongoose.connect(config.MONGO_URL, {
    useCreateIndex: true,
    useNewUrlParser: true
});

app.set('x-powered-by', false);
app.use(cors());
app.use(bodyParser.json());

app.use(
    cookieSession({
        maxAge: 30 * 24 * 60 * 60 * 1000,
        name: 'session',
        keys: [config.COOKIE_KEY]
    })
);
app.use(cookieParser());

app.use(passport.initialize());
app.use(passport.session());

app.use("/auth", authRoutes);

app.use(morgan('dev'))

module.exports = app;
