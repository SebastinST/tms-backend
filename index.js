const express = require('express');
const session = require('express-session');
const router = express.Router();
const port = 3000;

// Inititalize the app and add middleware
const app = express();
app.use(express.json());
app.use(session({secret: 'super-secret'})); // Session setup


/** U1: Login & Logout **/ 

// User login
// POST to '/login'
app.post('/login', (req, res) => {
  const {username, password} = req.body;

  // DB select user account based on 'username'
    // Check for valid user account
    
  // Check user account password != provided password
    
  // Return login success

  if (username === 'bob' && password === '1234') {
    req.session.isLoggedIn = true;
    res.redirect(req.query.redirect_url ? req.query.redirect_url : '/');
  } else {
    res.render('login', {error: 'Username or password is incorrect'});
  }
});

// User logout
// GET to '/logout'
app.get('/logout', (req, res) => {
  // Remove cookies
  req.session.isLoggedIn = false;

  // Return logout success
});
/** End of U1: Login & Logout **/ 

/** U2: Update Account **/ 
// Show current user account details
// GET to '/getSelf'
app.get('/getSelf', (req, res) => {
  
  // Get username from token

  // DB select user account details based on username
  
  // Return user account details
});

// Update current user account details
// POST to '/updateSelf'
app.post('/updateSelf', (req, res) => {
  const {email, password} = req.body;

  // Get username from token

  // Check if email is provided, it is valid 
  // Check if password is provided, it is valid

  // Check if either email or password is provided
    // DB update user account details based on username
      // if email is given, update email
      // if password is given, update password
  
  // Return successful update
});
/** End of U2: Update Account **/ 

/** A1: Manage Accounts **/ 
// Create user group
// POST to '/createGroup'
app.post('/createGroup', (req, res) => {
  const {group_name} = req.body;

  // Check if group_name is valid

  // DB create group with group_name

  // Return successful creation

})

// Create user account
// POST to '/createUser'
app.post('/createUser', (req, res) => {
  const { username, password, email, group_list} = req.body;
  
  // Check username and password provided and valid

  // DB create user with given details

  // Return successful creation
});

// Show all user account details
// GET to '/getAllUsers'
app.get('/getAllUsers', (req, res) => {
  
  // DB select all users account details

  // Return all users account details

});

// Update user account
// POST to '/updateUser'
app.post('/updateUser', (req, res) => {
  const {username, email, password, group_list} = req.body;

  // Check password is provided and valid

  // DB update user account details based on username
    // if email is given, update email
    // if password is given, update password
  
  // Return successful update

});

// Toggle user account status
// POST to '/toggleUserStatus'
app.post('/toggleUserStatus', (req, res) => {
  const {username} = req.body;

  // DB toggle user account status based on username

  // Return successful update

});
/** End of A1: Manage Accounts **/ 


/** App listening on port */
app.listen(port, () => {
  console.log(`TMS at http://localhost:${port}`);
});