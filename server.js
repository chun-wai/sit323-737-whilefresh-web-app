// 1. import the express modules
const express = require("express");
const app = express();
const fs = require('fs');
const winston = require('winston');
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const JWTstrategy = require("passport-jwt").Strategy;
const secureRoutes = require('./secureRoutes');
const demoLocal = require("./demoLocal.json");
const path = require("path");
const passport = require("passport");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcrypt");
const localStrategy = require("passport-local").Strategy;
const users = require("./users.json");

// 2. set up the views directory and the view engine (EJS)
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");


// 3. Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, "public")));

// 4. Parse request bodies
app.use(bodyParser.urlencoded({ extended: false }));

// 5. Initialize Passport.js middleware
app.use(passport.initialize());

// 6. Set up secure routes using 'secureRoutes' module
app.use("/user", secureRoutes);

// 7. Define a route for the root directory ("/") to render the index page
app.get("/", (req, res) => {
    res.render("index");
  });

function getJwt() {
    console.log("in getJwt");
    return demoLocal.Authorization?.substring(7); // remove the "bearer" from the token
}

// 8. Implement Passport.js authentication strategies:
passport.use(
    new JWTstrategy(
        {
            secretOrKey: "LITTLE_SECRET",
            jwtFromRequest: getJwt,
        },
        async (token, done) => {
            console.log("in jwt strat. token: ", token);

            if (token?.user?.email == "tokenerror") {
                let testError = new Error(
                    "Something bad happened. tokenerror"
                );
                return done(testError, false);
            }

            if (token?.user?.email == "emptytoken") {
                return done(null,false);
            }
            //3. successfully decoded and validated user:
            return done(null, token.user);
            
        }
    )
);

// Local strategy for login:
passport.use(
    "login",
    new localStrategy({usernameField: "email", passwordField: "password"}, async (email, password, done) => {
        console.log("login named");

        try {
            if (email === "apperror") {
                throw new Error(
                    "Error report"
                );
            }

            const user = users.find((user) => user.email === email);

            if (!user) {
                return done(null, false, { message: "User not found!"});
            }

            const passwordMatches = await bcrypt.compare(password, user.password);

            if (!passwordMatches) {
                return done(null, false, { message: "Invalid credentials!"});
            }

            return done(null, user, {
                message: "Hey congrats! you are logged in!",
            })
        } catch (error) {
            return done(error); // application error
        }
    })
)

// Local strategy for signup:
passport.use(
  "signup",
  new localStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      try {
        if (password.length <= 4 || !email) {
          done(null, false, {
            message: "Your credentials do not match our criteria",
          });
        } else {
          const hashedPass = await bcrypt.hash(password, 10);
          let newUser = { email, password: hashedPass, id: uuidv4() };
          users.push(newUser);
          await fs.writeFile("users.json", JSON.stringify(users), (err) => {
            if (err) return done(err);
            console.log("Updated the demo database");
          });

          // Display "Signed up successfully!" message
          done(null, newUser, { message: "Signed up successfully!" });
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);
  
  // Redirect to the dashboard route
  function redirectToDashboard(done, newUser) {
    done(null, newUser, { message: "Redirecting to dashboard..." });
  }


// 9. Implement routes for login, signup, and secure routes:
app.get("/secureroute", passport.authenticate("jwt", {session: false}), async (req, res) => {

    console.log("req.isAuthenticated: ", req.isAuthenticated());
    console.log("req.user: ", req.user); // passport does this for me
    console.log("req.login: ", req.login);
    // console.log("req.logout: ", req.logout);

    // res.send(`welcome to the top secret place ${req.user.email}, entering adding function in 5 seconds`);
    
    setTimeout(() => {
        res.redirect("/add/?n1=1&n2=2");
      }, 5000);

});

app.get("/logout", async (req, res) =>{

    await fs.writeFile(
        "demoLocal.json",
        JSON.stringify({ Authorization: ``}),
        (err) => {
            if (err) throw err;
        }
    )

    res.redirect("/login");
});

app.get('/login', async (req, res) => {
    const user = req.user; 
    res.render('login', { user: user });
  });

app.get('/signup', async (req, res) => {
    const user = req.user;
    res.render('signup', { user: user });
});
  

app.get("/failed", (req, res, next) => {
    res.send(`failed! ${req.query?.message}`);
});

app.get("/success", (req, res, next) => {
    res.send(`success! ${req.query?.message}`);
});

// login route
app.post("/login", (req, res, next) => {
  passport.authenticate("login", async (error, user, info) => {
    if (error) {
      return next(error);
    }

    if (!user) {
      return res.redirect(`/failed?message=${info.message}`);
    }

    const body = { _id: user.id, email: user.email };

    const token = jwt.sign({ user: body }, "LITTLE_SECRET");

    await fs.writeFile(
      "demoLocal.json",
      JSON.stringify({ Authorization: `Bearer ${token}` }),
      (err) => {
        if (err) throw err;
      }
    );

    // Render the loginsuccess.ejs template and pass the user object
    res.render("loginsuccess", { user });

  })(req, res, next);
});


// loginsuccess route
app.get("/loginsuccess", (req, res) => {
  res.render("loginsuccess", { user: req.user }); // Render the loginsuccess.ejs view and pass the user object
});


// Redirect to the dashboard route
function redirectToDashboard(req, res) {
  res.redirect("/signupsuccess");
}

app.get("/signupsuccess", (req, res) => {
  res.render("signupsuccess", { user: req.user });
});


// signup route
app.post("/signup", async (req, res, next) => {
  passport.authenticate("signup", async function (error, user, info) {
    if (error) return next(error);

    if (!user) return res.redirect(`/failed?message=${info.message}`);

    const body = { _id: user.id, email: user.email };

    const token = jwt.sign({ user: body }, "LITTLE_SECRET");

    await fs.writeFile(
      "demoLocal.json",
      JSON.stringify({ Authorization: `Bearer ${token}` }),
      (err) => {
        if (err) throw err;
      }
    );

    redirectToDashboard(req, res); // Call the function inside the route handler
  })(req, res, next);
});


// Dashboard route
app.get("/dashboard", ensureAuthenticated, (req, res) => {
    // Handle the dashboard logic
    res.render("dashboard", { user: req.user });
  });
  
  // Middleware to ensure user is authenticated
  function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      // If the user is authenticated, proceed to the next middleware/route handler
      return next();
    }
  
    // If the user is not authenticated, redirect to the login page
    res.redirect("/login");
  }


const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'calculate-service' },
    transports: [
      //
      // - Write all logs with importance level of `error` or less to `error.log`
      // - Write all logs with importance level of `info` or less to `combined.log`
      //
      new winston.transports.File({ filename: 'error.log', level: 'error' }),
      new winston.transports.File({ filename: 'combined.log' }),
    ],
  });
  
  //
  // If we're not in production then log to the `console` with the format:
  // `${info.level}: ${info.message} JSON.stringify({ ...rest }) `
  //
  if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
      format: winston.format.simple(),
    }));
  }

  // Writing a function to add two numbers
const add= (n1,n2) => {
    return n1+n2;
}

app.get("/add", passport.authenticate("jwt", {session: false}), (req, res) => {
//app.get("/add", (req,res)=>{
    try{
    const n1= parseFloat(req.query.n1);
    const n2=parseFloat(req.query.n2);
    if(isNaN(n1)) {
        logger.error("n1 is incorrectly defined");
        throw new Error("n1 incorrectly defined");
    }
    if(isNaN(n2)) {
        logger.error("n2 is incorrectly defined");
        throw new Error("n2 incorrectly defined");
    }
    
    if (n1 === NaN || n2 === NaN) {
        console.log()
        throw new Error("Parsing Error");
    }
    logger.info('Parameters '+n1+' and '+n2+' received for addition');
    const result = add(n1,n2);
    res.status(200).json({statuscocde:200, data: result }); 
    } catch(error) { 
        console.error(error)
        res.status(500).json({statuscocde:500, msg: error.toString() })
      }
});

const port=3040;
app.listen(port,()=> {
    console.log("server listening to port " +port);
}) 