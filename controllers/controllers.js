const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

// checkGroup(username, group) to check if a user is in a group
exports.checkGroup = async function (username, group) {
  //get user from database
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username])
  if (row.length === 0) {
    return false
  }
  const user = row[0]
  //User can have multiple groups delimited by ,{group},{group}. We need to split them into an array
  user.group_list = user.group_list.split(",")
  //if any of the user's groups is included in the roles array, then the user is authorized. The group has to match exactly
  //for each group in the group array, check match exact as group parameter
  authorised = user.group_list.includes(group)
  if (!authorised) {
    return false
  }
  return true
}

exports.checkLogin = async function (token) {
  if (token === "null" || !token) {
    return false
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET)
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [decoded.username])
  const user = row[0]

  if (user.is_disabled === 1) {
    return false
  }
  return true
}
