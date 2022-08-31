require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook');
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.OUR_SECRET,         // Defined in .env file
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

/////////////////////////////////////////// User schema (blueprint) for database ///////////////////////////////////////////

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

////////////////////////////////////////////// User schema (blueprint) plugins /////////////////////////////////////////////

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

///////////////////////////////////////////// Use the blueprint in a new model /////////////////////////////////////////////

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//////////////////////////////////////////// PassportJS Serialize & Deserialize ////////////////////////////////////////////

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

//////////////////////////////////////////// Google login strategy for PassportJS //////////////////////////////////////////

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,            // Defined in .env file
    clientSecret: process.env.CLIENT_SECRET,    // Defined in .env file
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

////////////////////////////////////////// Facebook login strategy for PassportJS //////////////////////////////////////////

passport.use(new FacebookStrategy({
    clientID: process.env['FACEBOOK_CLIENT_ID'],            // Defined in .env file
    clientSecret: process.env['FACEBOOK_CLIENT_SECRET'],    // Defined in .env file
    callbackURL: 'http://localhost:3000/oauth2/redirect/facebook',
    state: true
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

//////////////////////////////////////////////////////// GET routes ////////////////////////////////////////////////////////

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get('/auth/facebook',

    passport.authenticate('facebook'));

app.get('/login/federated/facebook',
    passport.authenticate('facebook')
);

app.get("/oauth2/redirect/facebook",
    passport.authenticate('facebook', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect secrets page.
        res.redirect("/secrets");
    });

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    });

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", { usersWithSecrets: foundUsers });
            }
        }
    });
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });

});

//////////////////////////////////////////////////////// POST routes ///////////////////////////////////////////////////////

app.post("/register", function (req, res) {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
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
        password: req.body.password
    });

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

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets")
                });
            }
        }
    });
});

/////////////////////////////////////////////////////// Launch server //////////////////////////////////////////////////////

app.listen(3000, function () {
    console.log("Server started on port 3000.");
});
