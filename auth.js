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
    if (req.body.username == "admin" && req.user != "admin") {
        res.status(401).json({
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