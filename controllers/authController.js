const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")
const jwt = require("jsonwebtoken")

exports.loginUser = catchAsyncErrors(async (req, res, next) => {
  const { username, password } = req.body

  if (!username || !password) {
    return next(new ErrorResponse("Please provide an username and password", 400))
  }

  //find user in database
  connection.query("SELECT * FROM user WHERE username = ?", [username], async (error, result) => {
    if (error) {
      return next(new ErrorResponse("Internal Server Error", 500))
    }

    if (result.length === 0) {
      return next(new ErrorResponse("User does not exist", 401))
    }

    const user = result[0]

    if (user.password !== password) {
      return next(new ErrorResponse("Invalid credentials", 401))
    }

    sendToken(user, 200, res)
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

const getJwtToken = (user) => {
  return jwt.sign({ id: this.id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_TIME
  })
}
