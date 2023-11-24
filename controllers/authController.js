const connection = require("../config/database");
const jwt = require("jsonwebtoken");

/** U1: Login & Logout **/ 

// User login
// POST to '/login'
exports.login = async (req, res) => {
    const {username, password} = req.body;

    // DB select user account based on 'username'
    try {
        const result = await connection.promise().execute(
            "SELECT * FROM user WHERE username=?", 
            [username]
        )

        const user = result[0][0];
        
        // Check for valid user account, and password
        if (!user || user.is_disabled || password != user.password) {
            res.status(400).json({
                success : false,
                message : 'Error: Invalid login',
            });
            return;
        };

        // Handle valid login

        const token = jwt.sign(
            {username: user.username}, 
            process.env.JWT_SECRET, 
            {expiresIn: process.env.JWT_EXPIRES_TIME}
        )
        const options = {
            expires: new Date(Date.now() + process.env.COOKIE_EXPIRES_TIME * 24 * 60 * 60 * 1000),
            httpOnly: true
        }

        res.status(200).cookie("token", token, options).json({
            success: true,
            token,
            group_list: user.group_list
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