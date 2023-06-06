const express = require("express");
const passport = require("passport");
const router = express.Router();

router.all("*", function (req, res, next) {
    passport.authenticate("jwt", { session: false }, function (err, user, info) {
        console.log("router.all err: ", err?.message);
        console.log("router.all user: ", user);
        console.log("router.all info: ", info?.message);

        if (info) {
            console.log(
                "I happened because the token was either invalid or not present."
            );
            return res.send(info.message);
        }

        if (err) {
            console.log("tokenerror");
            return res.send(err.message);
        }

        if(!user) {
            return res.send(
                "false user"
            )
        }

        if (user) {
            console.log("req.login? ", req.login);
            req.isAuthenticated = true;
            req.user = user;
            return next();
        }
    })(req, res, next);
});

router.get("/profile", (req, res, next) => {
    console.log("--beginning of /profile--");
    console.log("isAuthenticated: ", req.isAuthenticated);

    console.log("req.user ", req.user);
    console.log("req.login: ", req.login);
    console.log("req.logout: ", req.logout);
    res.json({
        user: req.user,
        message: "Hello friend",
    });
});

router.get("/settings", (req, res, next) => {
    res.json({
        user: req.user,
        message: "Settings page",
    });
});

module.exports = router;