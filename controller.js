const connection = require("./config/database");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

/* U1: Login & Logout */ 

// User login
// POST to '/login'
exports.login = async (req, res) => {
    const {username, password} = req.body;
    
    // Add optional code to get hashed password for me 
    // to reset in DB if I forget
    // const hashedPassword = await bcrypt.hash("temp1234$", 10);
    // console.log(hashedPassword);
    
    if (!username || !password) {
      res.status(400).json({
          success : false,
          message : 'Error: Invalid login credentials',
      });
      return;
  };

    // DB select user account based on 'username'
    try {
        const result = await connection.promise().execute(
            "SELECT * FROM user WHERE username=?", 
            [username]
        )

        const user = result[0][0];
        
        // Check for valid user account
        if (!user) {
            res.status(400).json({
                success : false,
                message : 'Error: Invalid login credentials',
            });
            return;
        };

        //Use bcrypt to compare password
        const passwordsMatch = await bcrypt.compare(password, user.password);
        if (!passwordsMatch) {
          res.status(400).json({
            success : false,
            message : 'Error: Invalid login credentials',
          });
          return;
        }

        // Handle valid login

        const token = jwt.sign(
            {username: user.username}, 
            process.env.JWT_SECRET, 
            {expiresIn: process.env.JWT_EXPIRES_TIME}
        )
        // Setting expiry time for COOKIE_EXPIRES_TIME * 1 day (7 days)
        const options = {
            expires: new Date(Date.now() + process.env.COOKIE_EXPIRES_TIME * 24 * 60 * 60 * 1000),
            httpOnly: true
        }

        res.status(200).cookie("token", token, options).json({
            success: true,
            token
        })
        
    } catch(e) {
        res.status(500).json({
            success : false,
            message : e
        });
        return;
    }
};

// User logout
// GET to '/_logout'
exports._logout = (req, res) => {
    // Remove cookies
    res.cookie('token', 'none', {
        expires : new Date(Date.now()),
        httpOnly : true
    });

    // Return logout success
    res.status(200).json({
        success : true,
        message : 'Success: User logged out'
    });
};
/* End of U1: Login & Logout */ 

/* U2: Update Account */ 
// Show current user account details
// GET to '/getSelf'
exports.getSelf = async (req, res) => {
  
    // Get username from token
    const username = req.user.username;
    
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
};
  
// Update current user account details
// POST to '/updateSelf'
exports.updateSelf = async (req, res) => {
    // Assume email always given (previous value if unchanged)
    const {password, email} = req.body;
  
    // Get username from token
    const username = req.user.username;
    
    // DB update user account details based on username
    try {

      // Check if password is provided, 8 > character > 10 and only include alphanumeric, number and special character
      if (password) {
        const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
        if (!passwordRegex.test(password)) {
          res.status(400).json({
            success : false,
            message : 'Error: Password must be 8-10 characters long, contain at least one number, one letter and one special character',
          })
          return;
        }
      
        // Encrypt valid password with salt 10
        const hashedPassword = await bcrypt.hash(password, 10);

        result = await connection.promise().execute(
          "UPDATE user SET password=?,email=? WHERE username=?", 
          [hashedPassword, email, username]
        )
      } else {
        result = await connection.promise().execute(
          "UPDATE user SET email=? WHERE username=?", 
          [email, username]
        )
      }
      
  
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
        message : `Success: Your details have been updated`,
      })
    } catch (e) {
      res.status(500).json({
        success : false,
        message : e
      });
      return;
    }
};
/* End of U2: Update Account */ 
  
/* A1: Manage Accounts */ 
// Create user group
// POST to '/createGroup'
exports.createGroup = async (req, res) => {
    const {group_name} = req.body;
  
    // Check if group_name is only alphanumeric and contains no spaces
    const groupnameRegex = /^[0-9a-zA-Z]+$/
    if (!groupnameRegex.test(group_name)) {
      res.status(400).json({
        success : false,
        message : 'Error: Groupname can only be alphanumeric and contain no spaces',
      })
      return;
    }
  
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
      if (e.code === "ER_DUP_ENTRY") {
        res.status(500).json({
          success : false,
          message : `Error: Group '${group_name}' already exists`
        });
        return;  
      }
      res.status(500).json({
        success : false,
        message : e
      });
      return;
    }
};
  
// Create user account
// POST to '/createUser'
exports.createUser = async (req, res) => {
    let { username, password, email, group_list } = req.body;
    
    // Check if password is provided, 8 > character > 10 and only include alphanumeric, number and special character
    const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
    if (!passwordRegex.test(password)) {
      res.status(400).json({
        success : false,
        message : 'Error: Password must be 8-10 characters long, contain at least one number, one letter and one special character',
      })
      return;
    }

    // Encrypt valid password with salt 10
    const hashedPassword = await bcrypt.hash(password, 10);

    // DB create user with given details
    if (!email) {email = null};
    if (!group_list) {group_list = null};
    try {
      const result = await connection.promise().execute(
        "INSERT INTO user (username, password, email, `group_list`, is_disabled) VALUES (?,?,?,?,?)", 
        [username, hashedPassword, email, group_list, 0]
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
      if (e.code === "ER_DUP_ENTRY") {
        res.status(500).json({
          success : false,
          message : `Error: User '${username}' already exists`
        });
        return;  
      }
      res.status(500).json({
        success : false,
        message : e
      });
      return;
    }
  };
  
// Show all user account details
// GET to '/getAllUsers'
exports.getAllUsers = async (req, res) => {

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
  
};
  
// Show all user group details
// GET to '/getAllGroups'
exports.getAllGroups = async (req, res) => {
    
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
};
  
// Update user account
// POST to '/updateUser'
exports.updateUser = async (req, res) => {
    // Assume all fields given (previous value if unchanged)
    const {username, email, password, group_list} = req.body;

    // DB update user account details based on username
    try {
      if (password) {
        // Check if password is provided, 8 > character > 10 and only include alphanumeric, number and special character
        const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
        if (!passwordRegex.test(password)) {
          res.status(400).json({
            success : false,
            message : 'Error: Password must be 8-10 characters long, contain at least one number, one letter and one special character',
          })
        return;
        }

        // Encrypt valid password with salt 10
        const hashedPassword = await bcrypt.hash(password, 10);

        result = await connection.promise().execute(
          "UPDATE user SET email=?,password=?,group_list=? WHERE username=?", 
          [email, hashedPassword, group_list, username]
        )
      } else {
        result = await connection.promise().execute(
          "UPDATE user SET email=?,group_list=? WHERE username=?", 
          [email, group_list, username]
        )
      }
  
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
};

// POST to '/toggleUserStatus'
exports.toggleUserStatus = async (req, res) => {
  const {username, is_disabled} = req.body;

  try {
    result = await connection.promise().execute(
      "UPDATE user SET is_disabled=? WHERE username=?", 
      [is_disabled, username]
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
};
/* End of A1: Manage Accounts */ 