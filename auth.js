// Check if the user is authenticated or not
const jwt = require("jsonwebtoken")
const connection = require("./config/database")

// Check user token and user disabled status
exports.isUserValid = async (req, res, next) => {
    try {
        // Placeholders for token and decoded token
        let token;
        let decoded;

        try {
            // if valid token then try to decrypt
            if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
                token = req.headers.authorization.split(" ")[1]
            }
            decoded = jwt.verify(token, process.env.JWT_SECRET)

        } catch (e) {
            // if invalid token or error verifying
            res.status(401).json({
                success : false,
                message : 'Error: User need to be logged in',
            })
            return;
        }
        
        // Get user from DB and add to request
        const result = await connection.promise().query(
            "SELECT * FROM user WHERE username = ?", 
            [decoded.username]
        )
        req.user = result[0][0];

        // Check for disabled user
        if (req.user.is_disabled === 1) {
            res.status(401).json({
                success : false,
                message : 'Error: User is disabled',
            })
            return;
        }

        next();
    } catch (e) {
        res.status(500).json({
            success : false,
            message : e,
        })
        return;
    }
    
};

// Check authorized groups
exports.authorizedGroups = (...roles) => {
  return (req, res, next) => {
    let authorised = 0;

    //User can have multiple groups delimited by ,{group},{group}. We need to split them into an array
    if (req.user.group_list) {
        req.user.group_list = req.user.group_list.split(",");
        //if any of the user's groups is included in the roles array, then the user is authorized
        authorised = req.user.group_list.some(r => roles.includes(r));
    }
    
    if (!authorised) {
        res.status(403).json({
            success : false,
            message : 'Error: User is not authorized for this',
        })
        return;
    }
    next();
  }
}

// Add protection for editing root admin details
exports.protectAdmin = async (req, res, next) => {
    if (req.body.username == "admin" && req.user.username != "admin") {
        res.status(403).json({
            success : false,
            message : 'Error: Admin cannot be edited',
        })
        return;
    } else {
        next();
    }
}

// Specification checkingGroup callback function
    // Exposes Checkgroup to route Checkgroup
exports.checkingGroup = async (req, res) => {
    const username = req.user.username;
    const group = req.body.groupname;
    try {
        const result = await Checkgroup(username, group);
        
        // Return successful check
        return res.status(200).json({
            result : result
        })
    } catch (e) {
      res.status(500).json({
        success : false,
        message : e
      });
      return;
    }
}

// Actual Checkgroup function that returns a value to indicate if a user is in a group
async function Checkgroup(userid, groupname) {
    const result = await connection.promise().query(
        "SELECT * FROM user WHERE username = ? AND group_list LIKE ?", 
        [userid, `%,${groupname},%`]
    )
    if (result[0][0]) {
        return true;
    } else {
        return false;
    } 
}

// Get current task and app details to add in request
// For anything to do with tasks
exports.getTaskAndApp = async (req, res, next) => {
    try {
        if (req.body.Task_id) {
            // Get current task_id requested
            const Task_id = req.body.Task_id
    
            //Check if the required parameter is not provided
            if (!Task_id) {
                res.status(400).json({
                success : false,
                message : 'Error: Task ID must be provided',
                })
                return;
            }
            // Get task current state from DB
            let getTask = await connection.promise().execute(
                "SELECT * FROM task WHERE `Task_id`=?",
                [Task_id]
            );
            
            // Put current task details in request
            req.task = getTask[0][0];
    
            // Get application information from DB
            let getApp = await connection.promise().execute(
                "SELECT * FROM application WHERE `App_Acronym`=?",
                [req.task.Task_app_Acronym]
            );
            
            // Put current app details in request
            req.app = getApp[0][0];
        } 
        if (req.body.Task_app_Acronym) {
            // Get application information from DB
            let getApp = await connection.promise().execute(
                "SELECT * FROM application WHERE `App_Acronym`=?",
                [req.body.Task_app_Acronym]
            );
            
            // Put current app details in request
            req.app = getApp[0][0];
        }
    } catch(e) {
        res.status(500).json({
            success : false,
            message : 'Error: Cannot get task/application',
        })
        return;
    }

    next();
}

// Check if user can EDIT current Task_id (check permit columns in app table)
// For changes in task state / plan
exports.isUserPermitted = async (req, res, next) => {
    // Variable to store permitted group for task requested
    let permittedGroup;

    const task = req.task;

    if (task) {
        switch (task.Task_state) {
            case "Open":
                permittedGroup = req.app.App_permit_Open;
                break;
            case "ToDo":
                permittedGroup = req.app.App_permit_toDoList;
                break;
            case "Doing":
                permittedGroup = req.app.App_permit_Doing;
                break;
            case "Done":
                permittedGroup = req.app.App_permit_Done;
                break;
        }
    } else {
        permittedGroup = req.app.App_permit_create;
    }
    

    // Return error if no permitted group specified or user does not have permitted group
    if (!permittedGroup || !req.user.group_list.includes(`,${permittedGroup},`)) {
        res.status(403).json({
            success : false,
            message : `Error: User '${req.user.username}' is not authorised`,
        })
        return;
    } else {
        next();
    }
}