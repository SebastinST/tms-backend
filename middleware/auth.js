// Check if the user is authenticated or not
const jwt = require("jsonwebtoken")
const catchAsyncErrors = require("./catchAsyncErrors")
const ErrorHandler = require("../utils/errorHandler")
const connection = require("../config/database")

exports.isAuthenticatedUser = catchAsyncErrors(async (req, res, next) => {
  let token

  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1]
  }

  if (token === "null" || !token) {
    return next(new ErrorHandler("Login first to access this resource.", 401))
  }
  let decoded
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET)
  } catch (err) {
    return next(new ErrorHandler("Login first to access this resource.", 401))
  }
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [decoded.username])
  req.user = row[0]

  if (req.user.is_disabled === 1) {
    return next(new ErrorHandler("User is disabled", 401))
  }
  next()
})

// handling users roles
exports.authorizeRoles = (...roles) => {
  return (req, res, next) => {
    console.log(req)
    //User can have multiple groups delimited by ,{group},{group}. We need to split them into an array
    req.user.group_list = req.user.group_list.split(",")
    //if any of the user's groups is included in the roles array, then the user is authorized
    authorised = req.user.group_list.some(r => roles.includes(r))
    if (!authorised) {
      return next(new ErrorHandler(`Role (${req.user.group_list}) is not allowed to access this resource`, 403))
    }
    next()
  }
}

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
