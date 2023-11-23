const express = require("express");
const session = require("express-session");
const app = express();
const port = 3000;

//Hello there

// Inititalize the app and add middleware
app.use(express.json());
app.use(session({ secret: "super-secret" })); // Session setup

/** U1: Login & Logout **/
// Login interface
app.get("/login", (req, res) => {
  if (req.session.isLoggedIn === true) {
    return res.redirect("/");
  }
  res.render("login", { error: false });
});

// Login attempt
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === "bob" && password === "1234") {
    req.session.isLoggedIn = true;
    res.redirect(req.query.redirect_url ? req.query.redirect_url : "/");
  } else {
    res.render("login", { error: "Username or password is incorrect" });
  }
});

// Logout interface
app.get("/logout", (req, res) => {
  req.session.isLoggedIn = false;
  res.redirect("/");
});
/** End of U1: Login & Logout **/

/** U2: Update Account **/
// Account Interface
app.get("/", (req, res) => {
  res.render("index", { isLoggedIn: req.session.isLoggedIn });
});

// Account updating

/** End of U2: Update Account **/

/** A1: Manage Accounts **/
// Admin Interface

// Manage Accounts

/** End of A1: Manage Accounts **/

/** App listening on port */
app.listen(port, () => {
  console.log(`TMS at http://localhost:${port}`);
});
