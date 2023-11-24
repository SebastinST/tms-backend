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

  const decoded = jwt.verify(token, process.env.JWT_SECRET)
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