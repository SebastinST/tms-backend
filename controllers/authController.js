const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")

// Login a user => /login
exports.loginUser = catchAsyncErrors(async (req, res, next) => {
  //the
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

  //Use bcrypt to compare password
  /*const isPasswordMatched = await bcrypt.compare(password, user.password)
  if (!isPasswordMatched) {
    return next(new ErrorResponse("Invalid password", 401))
  }*/

  if (user.is_disabled === 1) {
    return next(new ErrorResponse("User is disabled", 401))
  }

  sendToken(user, 200, res)
})

// Logout a user => /_logout
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

// Create a user => /register
exports.registerUser = catchAsyncErrors(async (req, res, next) => {
  const { username, password, email, group_list } = req.body

  //We need to check for password constraint, minimum character is 8 and maximum character is 10. It should include alphanumeric, number and special character. We do not care baout uppercase and lowercase.
  const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
  if (!passwordRegex.test(password)) {
    return next(new ErrorResponse("Password must be 8-10 characters long, contain at least one number, one letter and one special character", 400))
  }

  //Bcrypt password with salt 10
  const hashedPassword = await bcrypt.hash(password, 10)

  const result = await connection.promise().execute("INSERT INTO user (username, password, email, `group_list`, is_disabled) VALUES (?,?,?,?,?)", [username, hashedPassword, email, group_list, 0])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create user", 500))
  }

  res.status(200).json({
    success: true,
    message: "User created successfully"
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
    token,
    group_list: user.group_list
  })
}

const getJwtToken = user => {
  return jwt.sign({ username: user.username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_TIME
  })
}