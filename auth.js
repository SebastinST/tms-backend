// Check if the user is authenticated or not
const jwt = require("jsonwebtoken")
const connection = require("./config/database")

// Check if user is logged in and not disabled
exports.isUserValid = async (req, res, next) => {
    try {
        let token;

        if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
            token = req.headers.authorization.split(" ")[1]
        }

        if (token === "null" || !token) {
            res.status(401).json({
                success : false,
                message : 'Error: User need to be logged in',
            })
            return;
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET)
        const [row, fields] = await connection.promise().query(
            "SELECT * FROM user WHERE username = ?", 
            [decoded.username]
        )
        req.user = row[0]

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