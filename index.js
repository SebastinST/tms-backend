const express = require('express');
const dotenv = require("dotenv");

//Setting up config.env file variable
dotenv.config({ path: "./config/config.env" });

//Setting up database connection
const connection = require("./config/database");

// Inititalize the app and add middleware
const app = express();
app.use(express.json());

//Importing routes
const auth = require("./routes/authRouter")
// const user = require("./routes/userRouter")

//Mounting routes
app.use("/", auth)
// app.use("/userController", user)


/** U2: Update Account **/ 
// Show current user account details
// GET to '/getSelf'
app.get('/getSelf', async (req, res) => {
  
  // Get username from token
  const username = req.query.username;
  
  // DB select user account based on 'username'
  try {
    const result = await connection.promise().execute(
      "SELECT username, email, group_list FROM user WHERE username=?", 
      [username]
    )
    
    // Return user account details
    return res.status(200).json({
      success : true,
      message : `Success: User '${username}' details returned`,
      data : result[0][0]
    });
    
  } catch(e) {
    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }
});

// Update current user account details
// POST to '/updateSelf'
app.post('/updateSelf', async (req, res) => {
  // Assume email and password always given (previous value if unchanged)
  const {password, email} = req.body;

  // Get username from token
  const username = req.query.username;
  
  // Check if password is provided, it is valid

  // DB update user account details based on username
  try {
    const result = await connection.promise().execute(
      "UPDATE user SET password=?,email=? WHERE username=?", 
      [password, email, username]
    )

    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Updating user',
      })
      return;
    }

    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: User '${username}' details updated`,
    })
  } catch (e) {
    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }
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
      })
      return;
    };

    // Return successful creation
    return res.status(200).json({
      success : true,
      message : `Success: User group '${group_name}' created`,
    })

  } catch(e) {
    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }
})

// Create user account
// POST to '/createUser'
app.post('/createUser', async (req, res) => {
  let { username, password, email, group_list } = req.body;
  
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
      })
      return;
    };

    // Return successful creation
    return res.status(200).json({
      success : true,
      message : `Success: User '${username}' created`,
    })

  } catch(e) {
    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }
});

// Show all user account details
// GET to '/getAllUsers'
app.get('/getAllUsers', async (req, res) => {
  
  // DB select all users account details
  try {
    const result = await connection.promise().execute(
      "SELECT username, email, group_list, is_disabled FROM user"
    )
    
    // Return all users account details
    return res.status(200).json({
      success : true,
      message : 'Success: All user details returned',
      data : result[0]
    });
    
  } catch(e) {
    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }

});

// Show all user group details
// GET to '/getAllGroups'
app.get('/getAllGroups', async (req, res) => {
  
  // DB select all users groups details
  try {
    const result = await connection.promise().execute(
      "SELECT group_name FROM usergroups"
    )
    
    // Return all users account details
    return res.status(200).json({
      success : true,
      message : 'Success: All user groups returned',
      data : result[0]
    });
    
  } catch(e) {
    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }

});

// Update user account
// POST to '/updateUser'
app.post('/updateUser', async (req, res) => {
  // Assume all fields given (previous value if unchanged)
  const {username, email, password, group_list, is_disabled} = req.body;

  // Check password is provided and valid

  // DB update user account details based on username
  try {
    const result = await connection.promise().execute(
      "UPDATE user SET email=?,password=?,group_list=?,is_disabled=? WHERE username=?", 
      [email, password, group_list, is_disabled, username]
    )

    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Updating user',
      })
      return;
    }

    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: User '${username}' details updated`,
    })
  } catch (e) {
    res.status(500).json({
      success : false,
      message : e,
    });
    return;
  }
});
/** End of A1: Manage Accounts **/ 


/** App listening on port */
const PORT = process.env.PORT
app.listen(PORT, () => {
  console.log(`TMS at http://localhost:${PORT}`);
});