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
        if (!user || user.is_disabled) {
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

        res.status(200).json({
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
      message : `Success: User '${username}' status changed`,
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

/* Assigment 2: Task Management */ 

/* L1: Application Routes */
// Show all application details
// GET to '/getAllApps'
exports.getAllApps = async (req, res) => {
    
  // DB select all application details
  try {
    const result = await connection.promise().execute(
      "SELECT * FROM application"
    )
    
    // Return all users account details
    return res.status(200).json({
      success : true,
      message : 'Success: All applications returned',
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

// Create application
// POST to '/createApp'
exports.createApp = async (req, res) => {
  let { 
    App_Acronym, 
    App_Description, 
    App_Rnumber, 
    App_startDate, 
    App_endDate, 
    App_permit_create, 
    App_permit_Open, 
    App_permit_toDoList, 
    App_permit_Doing, 
    App_permit_Done 
  } = req.body;
  
  //Check if any of the required parameters are not provided
  if (!App_Acronym || !App_Description || !App_Rnumber) {
    res.status(400).json({
      success : false,
      message : 'Error: App Acronym, App Description and App Rnumber must be provided',
    })
    return;
  }

  // Check App_Rnumber is not negative and not a float
  if (App_Rnumber < 0 || App_Rnumber % 1 !== 0) {
    res.status(400).json({
      success : false,
      message : 'Error: App Rnumber must not be negative or a float',
    })
    return;
  }

  // Handle optional parameters
  if (!App_startDate) {App_startDate = null}
  if (!App_endDate) {App_endDate = null}
  if (!App_permit_create) {App_permit_create = null}
  if (!App_permit_Open) {App_permit_Open = null}
  if (!App_permit_toDoList) {App_permit_toDoList = null}
  if (!App_permit_Doing) {App_permit_Doing = null}
  if (!App_permit_Done) {App_permit_Done = null}
  
  try {
    const result = await connection.promise().execute(
      "INSERT INTO application (`App_Acronym`,`App_Description`,`App_Rnumber`,`App_startDate`,`App_endDate`,`App_permit_create`,`App_permit_Open`,`App_permit_toDoList`,`App_permit_Doing`,`App_permit_Done`) VALUES (?,?,?,?,?,?,?,?,?,?)",
      [
        App_Acronym, 
        App_Description, 
        App_Rnumber, 
        App_startDate, 
        App_endDate, 
        App_permit_create, 
        App_permit_Open, 
        App_permit_toDoList, 
        App_permit_Doing, 
        App_permit_Done 
      ]
    )
    
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Issue creating application',
      })
      return;
    };

    // Return successful creation
    return res.status(200).json({
      success : true,
      message : `Success: Application '${App_Acronym}' created`,
    })

  } catch(e) {
    if (e.code === "ER_DUP_ENTRY") {
      res.status(500).json({
        success : false,
        message : `Error: Application '${App_Acronym}' already exists`
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

// Update application
// POST to '/updateApp'
exports.updateApp = async (req, res) => {
  let { 
    App_Acronym,
    App_Description, 
    App_startDate, 
    App_endDate, 
    App_permit_create, 
    App_permit_Open, 
    App_permit_toDoList, 
    App_permit_Doing, 
    App_permit_Done 
  } = req.body;

  //Check that app description is not null
  if (!App_Acronym) {
    res.status(400).json({
      success : false,
      message : 'Error: App Acronym must be provided',
    })
    return;
  }

  //Check that app description is not null
  if (!App_Description) {
    res.status(400).json({
      success : false,
      message : 'Error: App Description must be provided',
    })
    return;
  }

  // Handle optional parameters
  if (!App_startDate) {App_startDate = null}
  if (!App_endDate) {App_endDate = null}
  if (!App_permit_create) {App_permit_create = null}
  if (!App_permit_Open) {App_permit_Open = null}
  if (!App_permit_toDoList) {App_permit_toDoList = null}
  if (!App_permit_Doing) {App_permit_Doing = null}
  if (!App_permit_Done) {App_permit_Done = null}

  // DB update application details based on app acronym
  try {
    const result = await connection.promise().execute(
      "UPDATE application SET `App_Description`=?, `App_startDate`=?, `App_endDate`=?, `App_permit_create`=?, `App_permit_Open`=?, `App_permit_toDoList`=?, `App_permit_Doing`=?, `App_permit_Done`=? WHERE `App_Acronym`=?", 
      [
        App_Description,  
        App_startDate, 
        App_endDate, 
        App_permit_create, 
        App_permit_Open, 
        App_permit_toDoList, 
        App_permit_Doing, 
        App_permit_Done,
        App_Acronym
      ]
    )
    
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Issue updating application',
      })
      return;
    };

    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: Application '${App_Acronym}' updated`,
    })

  } catch (e) {
    res.status(500).json({
      success : false,
      message : e,
    });
    return;
  }
};
/* End of L1: Application Routes */

/* M1: Plan Routes */

// Random Color generator
const getRandomColor = () => {
  const letters = "0123456789ABCDEF"
  let color = "#"
  for (let i = 0; i < 6; i++) {
    color += letters[Math.floor(Math.random() * 16)]
  }

  return color
};

// Check Permit
const checkPermit = async (user, Task_id) => {
  // Check if user can edit current Task_id (check permit columns in app table)
  // Return current Task_state if permitted for task in current state
  let permittedGroup;
  let Task;
  try {
    // Get task current state from DB
    result = await connection.promise().execute(
      "SELECT * FROM task WHERE `Task_id`=?",
      [Task_id]
    );

    Task = result[0];

    // Get application information from DB
    let result = await connection.promise().execute(
      "SELECT * FROM application WHERE `App_Acronym`=?",
      [Task.Task_app_Acronym]
    );

    const application = result[0];
    
    // Get permitted group from application based on current task state
    switch (Task.Task_state) {
      case "Open":
        permittedGroup = application.App_permit_Open
        break
      case "ToDo":
        permittedGroup = application.App_permit_toDoList
        break
      case "Doing":
        permittedGroup = application.App_permit_Doing
        break
      case "Done":
        permittedGroup = application.App_permit_Done
        break
    }

  } catch {
    // Find out error code for not found app acronym/ task

    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }
  
  // Return error if no permitted group specified or user does not have permitted group
  if (!permittedGroup || user.group_list.includes(`,${permittedGroup},`)) {
    res.status(403).json({
      success : false,
      message : `Error: User ${user.username} is not authorised`,
    })
    return;
  } else {
    // Check if user group has permitted group
    return Task.Task_state;
  }
}

// M1: Show all plan details by app acronym
// GET to '/getPlansByApp'
exports.getPlansByApp = async (req, res) => {
  const App_Acronym = req.params.App_Acronym
  
  // DB select all plan details tagged to app
  try {
    const result = await connection.promise().execute(
      "SELECT * FROM plan WHERE `Plan_app_Acronym`=?",
      [App_Acronym]
    )
    
    // Return all plans tagged to app
    return res.status(200).json({
      success : true,
      message : `Success: All plans returned for App '${App_Acronym}'`,
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

// M1: Create plan
// POST to '/createPlan'
exports.createPlan = async (req, res) => {
  let { 
    Plan_MVP_name, 
    Plan_app_acronym, 
    Plan_color, 
    Plan_startDate, 
    Plan_endDate, 
  } = req.body;
  
  //Check if any of the required parameters are not provided
  if (!Plan_MVP_name || !Plan_app_acronym) {
    res.status(400).json({
      success : false,
      message : 'Error: Plan Name and App Acronym must be provided',
    })
    return;
  }

  // If Plan_color not provided, generate random color
  if (!Plan_color) {
    Plan_color = getRandomColor();
  }

  // Handle optional parameters
  if (!Plan_startDate) {Plan_startDate = null}
  if (!Plan_endDate) {Plan_endDate = null}
  
  try {
    const result = await connection.promise().execute(
      "INSERT INTO plan (`Plan_MVP_name`,`Plan_app_Acronym`,`Plan_color`,`Plan_startDate`,`Plan_endDate`) VALUES (?,?,?,?,?)", 
      [
        Plan_MVP_name, 
        Plan_app_acronym, 
        Plan_color, 
        Plan_startDate, 
        Plan_endDate, 
      ]
    )
    
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Issue creating plan',
      })
      return;
    };

    // Return successful creation
    return res.status(200).json({
      success : true,
      message : `Success: Plan '${Plan_MVP_name}' created`,
    })

  } catch(e) {
    if (e.code === "ER_DUP_ENTRY") {
      res.status(500).json({
        success : false,
        message : `Error: Plan '${App_Acronym}' already exists`
      });
      return;  
    }
    // Find out error code for not found app acronym

    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }
};

// M1: Update plan
// POST to '/updatePlan'
exports.updatePlan = async (req, res) => {
  let { 
    Plan_MVP_name, 
    Plan_app_acronym,
    Plan_startDate, 
    Plan_endDate, 
  } = req.body;

  //Check if any of the required parameters are not provided
  if (!Plan_MVP_name || !Plan_app_acronym) {
    res.status(400).json({
      success : false,
      message : 'Error: Plan Name and App Acronym must be provided',
    })
    return;
  }

  // Handle optional parameters
  if (!Plan_startDate) {Plan_startDate = null}
  if (!Plan_endDate) {Plan_endDate = null}

  // DB update plan details based on plan name and app acronym
  try {
    const result = await connection.promise().execute(
      "UPDATE plan SET `Plan_startDate`=?, `Plan_endDate`=? WHERE `Plan_MVP_name`=? AND `Plan_app_acronym`=?", 
      [ 
        Plan_startDate, 
        Plan_endDate, 
        Plan_MVP_name, 
        Plan_app_acronym,
      ]
    )
    
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Issue updating plan',
      })
      return;
    };

    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: Plan '${Plan_MVP_name}' in App '${Plan_app_acronym}' updated`,
    })

  } catch (e) {
    // TODO: Find out error code for not found app acronym

    res.status(500).json({
      success : false,
      message : e,
    });
    return;
  }
};
/* End of M1: Plan Routes */

/* Task Routes */

// U3: Show all tasks by app acronym
// GET to '/getTasksByApp'
exports.getTasksByApp = async (req, res) => {
  const App_Acronym = req.params.App_Acronym
  
  // DB select all tasks tagged to app
  try {
    const result = await connection.promise().execute(
      "SELECT `Task_name`, `Task_state`, `Plan_color` FROM task, plan WHERE `task.Task_plan` = `plan.Plan_MVP_name` AND `task.task_app_Acronym` = `plan.Plan_app_Acronym` AND `Task_app_Acronym`=?",
      [App_Acronym]
    )
    
    // Return all tasks tagged to app
    return res.status(200).json({
      success : true,
      message : `Success: All tasks for App '${App_Acronym}' returned`,
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

// L2: PL Create task
// POST to '/createTask'
exports.createTask = async (req, res) => {
  let { 
    Task_name, 
    Task_description, 
    Task_app_Acronym
  } = req.body;
  let username = req.user.username;
  
  //Check if any of the required parameters are not provided
  if (!Task_name || !Task_app_Acronym) {
    res.status(400).json({
      success : false,
      message : 'Error: Task Name and App Acronym must be provided',
    })
    return;
  }

  // Handle optional parameter
  if (!Task_description) {Task_description = null}

  // Get related application details
  try {
    let result = await connection.promise().execute(
      "SELECT `App_Rnumber` FROM application WHERE `App_Acronym`=?",
      [Task_app_Acronym]
    )
    const application = result[0];
    if (!application) {
      res.status(400).json({
        success : false,
        message : 'Error: App does not exist',
      })
      return;
    }
  } catch {
    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }

  // Generate task ID, check if string ok
  const Task_id = Task_app_Acronym + application.App_Rnumber;

  // Set default open state
  const Task_state = "Open";

  // Set initial notes for task as audit
  const currentDateTime = new Date().toLocaleString();
  const Task_notes = 
    `\n
    \nState: ${Task_state}
    \nUser: ${username}
    \nDatetime: ${currentDateTime}
    \n`
  
  // Set task creator and owner as current username
  const Task_creator = username;
  const Task_owner = username;
  
  try {
    let result = await connection.promise().execute(
      "INSERT INTO task (Task_name, Task_description, Task_notes, Task_id, Task_app_Acronym, Task_state, Task_creator, Task_owner) VALUES (?,?,?,?,?,?,?,?)", 
      [
        Task_name, 
        Task_description, 
        Task_notes,
        Task_id,
        Task_app_Acronym, 
        Task_state, 
        Task_creator, 
        Task_owner
      ]
    )
    
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Issue creating task',
      })
      return;
    };

    // Increment app Running number after successful creation
    result = await connection.promise().execute(
      "UPDATE application SET App_Rnumber = ? WHERE App_Acronym = ?", 
      [application.App_Rnumber + 1, Task_app_Acronym]
    )

    // Return successful creation
    return res.status(200).json({
      success : true,
      message : `Success: Task '${Task_id}' created`,
    })

  } catch(e) {
    if (e.code === "ER_DUP_ENTRY") {
      res.status(500).json({
        success : false,
        message : `Error: Task '${Task_id}' already exists`
      });
      return;  
    }
    // Find out error code for not found app acronym

    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }
};

// U3: Show task by id
// GET to '/getTaskById'
exports.getTaskById = async (req, res) => {
  const Task_id = req.params.Task_id
  
  //Check if the required parameter is not provided
  if (!Task_id) {
    res.status(400).json({
      success : false,
      message : 'Error: Task ID must be provided',
    })
    return;
  }

  // Get task details
  try {
    let result = await connection.promise().execute(
      "SELECT * FROM task WHERE `Task_id`=?",
      [Task_id]
    )
    
    // Return task
    return res.status(200).json({
      success : true,
      message : `Success: Task '${App_Acronym}' returned`,
      data : result[0]
    });

  } catch {
    res.status(500).json({
      success : false,
      message : e
    });
    return;
  }
};

// D1/D3: Dev add research/details in ToDo/Doing task state 
// POST to '/addTaskNotes'
exports.addTaskNotes = async (req, res) => {
  let {
    Task_id, 
    Task_notes
  } = req.body;

  // Get username from token
  const Task_owner = req.user.username;

  //Check if the required parameters are not provided
  if (!Task_notes || !Task_id) {
    res.status(400).json({
      success : false,
      message : 'Error: Task ID and Task notes must be provided',
    })
    return;
  }

  // Update notes with audit trail
  const currentDateTime = new Date().toLocaleString();
  Task_notes += 
  `\n
  \nNotes Added
  \nUser: ${Task_owner}
  \nDatetime: ${currentDateTime}
  \n`

  // Update task with new notes and update task owner
  try {
    result = await connection.promise().execute(
      "UPDATE task SET `Task_notes`=?, `Task_owner`=? WHERE `Task_id`=?", 
      [Task_notes, Task_owner, Task_id]
    )
  
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Updating task',
      })
      return;
    }
  
    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: Task '${Task_id}' updated`,
    })
  } catch (e) {
    res.status(500).json({
      success : false,
      message : e,
    });
    return;
  }
};

// M2: PM Release task 'Open' to 'ToDo'
// D2/D5: Start task 'ToDo' to 'Doing' or send for review task 'Doing' to 'Done'
// L3: Review and mark complete task 'Done' to 'Close'
// POST to '/promoteTask'
exports.promoteTask = async (req, res) => {
  let {
    Task_id,
    Task_notes,
    Task_app_Acronym
  } = req.body;

  // Get username from token
  const Task_owner = req.user.username;

  //Check if the required parameters are not provided
  if (!Task_notes || !Task_id || !Task_app_Acronym) {
    res.status(400).json({
      success : false,
      message : 'Error: Task ID, Task notes and App acronym must be provided',
    })
    return;
  }
  
  // Check if current user can promote current task
  const Task_state = await checkPermit(req.user, Task_id)

  //Depending on the current state, we will update the state to the next state
  let nextState;
  switch (Task_state) {
    case "Open":
      nextState = "ToDo"
      break
    case "ToDo":
      nextState = "Doing"
      break
    case "Doing":
      nextState = "Done"
      break
    case "Done":
      nextState = "Close"
      break
    default:
      nextState = "Close"
  }

  // Update notes with audit trail
  const currentDateTime = new Date().toLocaleString();
  Task_notes += 
  `\n
  \nPromoted to ${nextState} state
  \nUser: ${username}
  \nDatetime: ${currentDateTime}
  \n`

  // Update task with new notes and state and update task owner
  try {
    result = await connection.promise().execute(
      "UPDATE task SET `Task_notes`=?, `Task_state`=?, `Task_owner`=? WHERE `Task_id`=?", 
      [Task_notes, nextState, Task_owner, Task_id]
    )
  
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Promoting task',
      })
      return;
    }
  
    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: Task '${Task_id}' promoted`,
    })
  } catch (e) {
    res.status(500).json({
      success : false,
      message : e,
    });
    return;
  }
};

// L3: Review and reject task 'Done' to 'Doing'
// POST to '/rejectTask'
exports.rejectTask = async (req, res) => {
  let {
    Task_id,
    Task_notes,
    Task_plan,
    Task_app_Acronym
  } = req.body;

  // Get username from token
  const Task_owner = req.user.username;

  //Check if the required parameters are not provided
  if (!Task_notes || !Task_id || !Task_app_Acronym) {
    res.status(400).json({
      success : false,
      message : 'Error: Task ID, Task notes and App acronym must be provided',
    })
    return;
  }

  // Check if current user can reject current task
  await checkPermit(req.user, Task_id);

  //Depending on the current state, we will update the state to the next state
  let nextState = "Doing";
  
  // Handle optional parameter
  if (!Task_plan) {Task_plan = null};

  // Update notes with audit trail
  const currentDateTime = new Date().toLocaleString();
  Task_notes += 
  `\n
  \nRejected to ${nextState} state
  \nUser: ${username}
  \nDatetime: ${currentDateTime}
  \n`

  // Update task with new notes and state (and plan, if have) and update task owner
  try {
    result = await connection.promise().execute(
      "UPDATE task SET `Task_notes`=?, `Task_state`=?, `Task_owner`=?, `Task_plan`=? WHERE `Task_id`=?", 
      [Task_notes, nextState, Task_owner, Task_plan, Task_id]
    )
  
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Rejecting task',
      })
      return;
    }
  
    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: Task '${Task_id}' rejected`,
    })
  } catch (e) {
    res.status(500).json({
      success : false,
      message : e,
    });
    return;
  }
};

// D4: Dev Return task 'Doing' to 'ToDo'
// POST to '/returnTask'
exports.returnTask = async (req, res) => {
  let {
    Task_id,
    Task_notes
  } = req.body;

  // Get username from token
  const Task_owner = req.user.username;

  //Check if the required parameters are not provided
  if (!Task_notes || !Task_id) {
    res.status(400).json({
      success : false,
      message : 'Error: Task ID and Task notes must be provided',
    })
    return;
  }

  // Check if current user can return current task
  await checkPermit(req.user, Task_id);

  //Depending on the current state, we will update the state to the next state
  let nextState = "ToDo";

  // Update notes with audit trail
  const currentDateTime = new Date().toLocaleString();
  Task_notes += 
  `\n
  \nReturned to ${nextState} state
  \nUser: ${username}
  \nDatetime: ${currentDateTime}
  \n`

  // Update task with new notes and state (and plan, if have) and update task owner
  try {
    result = await connection.promise().execute(
      "UPDATE task SET `Task_notes`=?, `Task_state`=?, `Task_owner`=? WHERE `Task_id`=?", 
      [Task_notes, nextState, Task_owner, Task_id]
    )
  
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Returning task',
      })
      return;
    }
  
    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: Task '${Task_id}' returned`,
    })
  } catch (e) {
    res.status(500).json({
      success : false,
      message : e,
    });
    return;
  }
};

// M3: Assign Task to plan
// POST to '/assignTaskToPlan'
exports.assignTaskToPlan = async (req, res) => {
  let {
    Task_id,
    Task_notes,
    Task_plan
  } = req.body;

  // Get username from token
  const Task_owner = req.user.username;

  //Check if the required parameters are not provided
  if (!Task_notes || !Task_id) {
    res.status(400).json({
      success : false,
      message : 'Error: Task ID and Task notes must be provided',
    })
    return;
  }
  
  // Handle optional parameter
  if (!Task_plan) {Task_plan = null};

  // Update notes with audit trail
  const currentDateTime = new Date().toLocaleString();
  Task_notes += 
  `\n
  \nAssigned to ${Task_plan ? Task_plan: "no plan"}
  \nUser: ${username}
  \nDatetime: ${currentDateTime}
  \n`

  // Update task with new notes and state (and plan, if have) and update task owner
  try {
    result = await connection.promise().execute(
      "UPDATE task SET `Task_notes`=?, `Task_owner`=?, `Task_plan`=? WHERE `Task_id`=?", 
      [Task_notes, Task_owner, Task_plan, Task_id]
    )
  
    if (result[0].affectedRows === 0) {
      res.status(500).json({
        success : false,
        message : 'Error: Assigning plan',
      })
      return;
    }
  
    // Return successful update
    return res.status(200).json({
      success : true,
      message : `Success: Task '${Task_id}' assigned to ${Task_plan}`,
    })
  } catch (e) {
    // 
    res.status(500).json({
      success : false,
      message : e,
    });
    return;
  }
};

/* End of Task Routes */

/* End of Assigment 2 */ 