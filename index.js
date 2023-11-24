const express = require('express');
const session = require('express-session');
const dotenv = require("dotenv");

//Setting up config.env file variable
dotenv.config({ path: "./config/config.env" });

//Setting up database connection
const connection = require("./config/database");

// Inititalize the app and add middleware
const app = express();
app.use(express.json());
app.use(session({secret: 'super-secret'})); // Session setup


/** U1: Login & Logout **/ 

// User login
// POST to '/login'
app.post('/login', async (req, res) => {
  const {username, password} = req.body;

  // DB select user account based on 'username'
  try {
    const result = await connection.promise().execute(
      "SELECT * FROM user WHERE username=?", 
      [username]
    )
    
    // Check for valid user account
    if (result[0].length === 0) {
      res.status(400).json({
        success : false,
        message : 'Error: Invalid login',
      });
      return;
    };

    // Check user account password != provided password
    if (password == result[0][0].password) {
      // Return login success
      return res.status(200).json({
        success : true,
        message : 'User logged in',
        data : username
      });
    } else {
      res.status(400).json({
        success : false,
        message : 'Error: Invalid login',
      });
      return;
    }

  } catch(e) {
    res.status(500).json({
      success : false,
      message : `Error: ${e}`,
    });
    return;
  }
});

// User logout
// GET to '/_logout'
app.get('/_logout', (req, res) => {
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
app.post('/createGroup', async (req, res) => {
  const {group_name} = req.body;

  // Check if group_name is valid

  // DB create group with group_name
  try {
    const result = await connection.promise().execute(
      "INSERT INTO usergroups (group_name) VALUES (?)", 
      [group_name]
    )
    
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Issue creating user group',
        data : result
    })
    return;
    };

    // Return successful creation
    return res.status(200).json({
      success : true,
      message : 'User group created',
      data : result
    })

  } catch(e) {
    res.status(500).json({
      success : false,
      message : `Error:${e}`,
    });
    return;
  }
})

// Create user account
// POST to '/createUser'
app.post('/createUser', async (req, res) => {
  let { username, password, email, group_list} = req.body;
  
  // Check username and password provided and valid

  // DB create user with given details
  if (!email) {email = null};
  if (!group_list) {group_list = null};
  try {
    const result = await connection.promise().execute(
      "INSERT INTO user (username, password, email, `group_list`, is_disabled) VALUES (?,?,?,?,?)", 
      [username, password, email, group_list, 0]
    )
    
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Issue creating user',
        data : result
    })
    return;
    };

    // Return successful creation
    return res.status(200).json({
      success : true,
      message : 'User created',
      data : result
    })

  } catch(e) {
    res.status(500).json({
      success : false,
      message : `Error:${e}`,
    });
    return;
  }
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
const PORT = process.env.PORT
app.listen(PORT, () => {
  console.log(`TMS at http://localhost:${PORT}`);
});