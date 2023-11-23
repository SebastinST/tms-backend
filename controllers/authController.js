const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")
const jwt = require("jsonwebtoken")

// Login a user => /api/v1/login
exports.loginUser = catchAsyncErrors(async (req, res, next) => {
  const { username, password } = req.body

  if (!username || !password) {
    return next(new ErrorResponse("Please provide an username and password", 400))
  }

  //find user in database

  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username])
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 401))
  }

  const user = row[0]

  if (user.password !== password) {
    return next(new ErrorResponse("Invalid credentials", 401))
  }

  if (user.is_disabled === 1) {
    return next(new ErrorResponse("User is disabled", 401))
  }

  sendToken(user, 200, res)
})

// Logout a user => /api/v1/logout
exports.logout = catchAsyncErrors(async (req, res, next) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true
  })

  res.status(200).json({
    success: true,
    message: "Logged out"
  })
})

// Create a user => /api/v1/register
exports.registerUser = catchAsyncErrors(async (req, res, next) => {
  const { username, email, password, group } = req.body

  connection.query("INSERT INTO user (username, password, email, `groups`, is_disabled) VALUES (?,?,?,?,?)", [username, password, email, group, 0], async (error, result) => {
    if (error) {
      return next(new ErrorResponse("Failed to create user", 500))
    }

    res.status(200).json({
      success: true,
      message: "User created successfully"
    })
  })
})

// Create and send token and save in cookie
const sendToken = (user, statusCode, res) => {
  // Create JWT Token
  const token = getJwtToken(user)

  // Options for cookie
  const options = {
    expires: new Date(Date.now() + process.env.COOKIE_EXPIRES_TIME * 24 * 60 * 60 * 1000),
    httpOnly: true
  }

  // if(process.env.NODE_ENV === 'production ') {
  //     options.secure = true;
  // }

  res.status(statusCode).cookie("token", token, options).json({
    success: true,
    token
  })
}

const getJwtToken = user => {
  return jwt.sign({ username: user.username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_TIME
  })
}
