const express = require("express");
const app = express();
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");
require("dotenv").config();

const initializePassport = require("./passportConfig");
const initialize = require("./passportConfig");

initializePassport(passport);

const PORT = process.env.port || 4000;

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: false}));
app.use(
    session({
        secret:"secret",
        resave:false,

        saveUninitialized: false
    })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

app.get("/", (req, res) =>{
    res.render("index");
});

app.get("/users/register",checkAuthenticated, (req, res) => {
    res.render("register");
});

app.get("/users/login",checkAuthenticated, (req, res) =>{
    res.render("login");
});
app.get("/users/home", checkNotAuthenticated, (req, res) => {
    res.render("home", {user:req.user.name});
});

app.get("/users/logout", (req, res) =>{
  req.logOut();
  req.flash("success_msg","You have logged out");
  res.redirect("/users/login");
});

app.post("/users/register", async (req, res) => {
    let{ name, email, password, password2 } = req.body;

   

    console.log({
        name,
        email,
        password,
        password2
    });

    let errors = [];


    if (!name || !email || !password || !password2){
        errors.push({message: "Please enter all fields" });
    }

    if(password.length < 6) {
        errors.push({message: "Password should be alteast 6 character long "}); 
    }

    if(password != password2){
        errors.push({message: "Passwords do not match" });
    }

    if(errors.length > 0){
        res.render("register",{ errors, name, email, password, password2 });
    }else{
        let hasedPassword = await bcrypt.hash(password, 10);
        console.log(hasedPassword);

      
      
      
        pool.query(
            `SELECT * FROM users
            WHERE email = $1`,
            [email],
            (err, results) => {
                if (err) {
                    throw err;
                }
                console.log(results.rows);

                if (results.rows.lenght > 0) {
                    errors.push({messaga: "Email already registered"});
                    res.render('register',{errors});
                }else{
                    pool.query(
                        `INSERT INTO users (name, email, password)
                        VALUES ($1, $2, $3) 
                        RETURNING id, password`,
                         [name, email, hashedPassword],
                         (err, results) =>{
                             if (err) {
                                 throw err;
                             }
                             console.log(results.rows);
                             req.flash("success_msg", "You are now registered. Please log in");
                             res.redirect("/users/login");

                        }
                    );
                }
            }
        );
    }
});

app.post(
    "/users/login",
    passport.authenticate("local", {
     successRedirect: "/users/home",
     failureRedirect: "/users/login",
     failureFlash: true
 })
);
function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect("/users/home");
    }
    next();
}
function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
       return next()
    }
    res.redirect("/users/login");
}

app.listen(PORT, () =>{
    console.log(`server is running at port no ${PORT}`);
});