const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

// Get all users => /userController/getUsers
exports.getUsers = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection.promise().query("SELECT * FROM user")
  res.status(200).json({
    success: true,
    data: rows
  })
})

// Get a user => /userController/getUser/:username
exports.getUser = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username])
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404))
  }
  res.status(200).json({
    success: true,
    data: row[0]
  })
})

// Toggle user status => /userController/toggleUserStatus/:username
exports.toggleUserStatus = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username])
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404))
  }

  const user = row[0]
  //new status should be flip of current status
  const newStatus = user.is_disabled === 1 ? 0 : 1
  const result = await connection.promise().execute("UPDATE user SET is_disabled = ? WHERE username = ?", [newStatus, req.params.username])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500))
  }

  res.status(200).json({
    success: true,
    message: "User updated successfully"
  })
})

// Update a user (admin) => /userController/updateUser/:username
exports.updateUser = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username])
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404))
  }

  const user = row[0]

  //We need to check for password constraint, minimum character is 8 and maximum character is 10. It should include alphanumeric, number and special character. We do not care baout uppercase and lowercase.
  const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
  if (!passwordRegex.test(req.body.password)) {
    return next(new ErrorResponse("Password must be 8-10 characters long, contain at least one number, one letter and one special character", 400))
  }

  //bcrypt password with salt 10
  const hashedPassword = await bcrypt.hash(req.body.password, 10)

  //the fields are optional to update, so we need to build the query dynamically
  let query = "UPDATE user SET "
  let values = []
  //Updatable fields are email, password, groups.
  if (req.body.email) {
    query += "email = ?, "
    values.push(req.body.email)
  }
  if (req.body.password) {
    query += "password = ?, "
    values.push(hashedPassword)
  }
  if (req.body.group) {
    query += "`group_list` = ?, "
    values.push(req.body.group)
  }
  //remove the last comma and space
  query = query.slice(0, -2)
  //add the where clause
  query += " WHERE username = ?"
  values.push(req.params.username)
  const result = await connection.promise().execute(query, values)
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500))
  }

  res.status(200).json({
    success: true,
    message: "User updated successfully"
  })
})

// Update user email (user) => /userController/updateUserEmail/:username
exports.updateUserEmail = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username])
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404))
  }

  const user = row[0]
  const result = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, req.params.username])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500))
  }

  res.status(200).json({
    success: true,
    message: "User updated successfully"
  })
})

// Update user password (user) => /userController/updateUserPassword/:username
exports.updateUserPassword = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username])
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404))
  }

  const user = row[0]
  //Compare old password with the password in database
  const isPasswordMatched = await bcrypt.compare(req.body.old_password, user.password)
  if (!isPasswordMatched) {
    return next(new ErrorResponse("Invalid password", 401))
  }

  //bcrypt new password with salt 10
  const hashedPassword = await bcrypt.hash(req.body.password, 10)

  const result = await connection.promise().execute("UPDATE user SET password = ? WHERE username = ?", [req.body.password, req.params.username])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500))
  }

  sendToken(user, 200, res)
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
