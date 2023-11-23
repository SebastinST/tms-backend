const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")

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
    values.push(req.body.password)
  }
  if (req.body.group) {
    query += "`groups` = ?, "
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
  const result = await connection.promise().execute("UPDATE user SET password = ? WHERE username = ?", [req.body.password, req.params.username])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500))
  }

  res.status(200).json({
    success: true,
    message: "User updated successfully"
  })
})
