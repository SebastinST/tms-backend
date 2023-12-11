const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const mysql = require("mysql2")

//Setting up database connection
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
})
if (connection) console.log(`MySQL Database connected with host: ${process.env.DB_HOST}`)

// checkGroup(username, group) to check if a user is in a group
exports.Checkgroup = async function (userid, groupname) {
  //get user from database
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [userid])
  if (row.length === 0) {
    return false
  }
  const user = row[0]
  //User can have multiple groups delimited by ,{group},{group}. We need to split them into an array
  user.group_list = user.group_list.split(",")
  //if any of the user's groups is included in the roles array, then the user is authorized. The group has to match exactly
  //for each group in the group array, check match exact as group parameter
  authorised = user.group_list.includes(groupname)
  if (!authorised) {
    return false
  }
  return true
}

exports.checkLogin = catchAsyncErrors(async function (token) {
  if (token === "null" || !token) {
    return false
  }
  let decoded
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET)
  } catch (err) {
    return false
  }

  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [decoded.username])
  const user = row[0]
  if (user === undefined) {
    return false
  }

  if (user.is_disabled === 1) {
    return false
  }
  return true
})

// Login a user => /login
exports.loginUser = catchAsyncErrors(async (req, res, next) => {
  //get username and password from request body
  const { username, password } = req.body

  //check if username and password is provided
  if (!username || !password) {
    return next(new ErrorResponse("Invalid username or password", 400))
  }

  //find user in database
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username])
  if (row.length === 0) {
    return next(new ErrorResponse("Invalid username or password", 401))
  }
  //get user from row
  const user = row[0]

  //Use bcrypt to compare password
  const isPasswordMatched = await bcrypt.compare(password, user.password)
  if (!isPasswordMatched) {
    return next(new ErrorResponse("Invalid username or password", 401))
  }

  //Check if user is disabled
  if (user.is_disabled === 1) {
    return next(new ErrorResponse("Invalid username of password", 401))
  }

  //Send token
  sendToken(user, 200, res)
})

// Logout a user => /_logout
exports.logout = catchAsyncErrors(async (req, res, next) => {
  //Set cookie to null so that it will expire and user will not be able to access protected routes
  /*res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true
  })*/

  //Send response
  res.status(200).json({
    success: true,
    message: "Logged out"
  })
})

// Create a user => /register
exports.registerUser = catchAsyncErrors(async (req, res, next) => {
  const { username, password, email, group_list } = req.body

  if (req.body.username === "" || null) {
    return next(new ErrorResponse("Please enter input in the username", 400))
  }

  //We need to check for password constraint, minimum character is 8 and maximum character is 10. It should include alphanumeric, number and special character. We do not care baout uppercase and lowercase.
  const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
  if (!passwordRegex.test(password)) {
    return next(new ErrorResponse("Password must be 8-10 characters long, contain at least one number, one letter and one special character", 400))
  }

  //Bcrypt password with salt 10
  const hashedPassword = await bcrypt.hash(password, 10)
  let result
  try {
    result = await connection.promise().execute("INSERT INTO user (username, password, email, `group_list`, is_disabled) VALUES (?,?,?,?,?)", [username, hashedPassword, email, group_list, 0])
  } catch (err) {
    //check duplicate entry
    if (err.code === "ER_DUP_ENTRY") {
      return next(new ErrorResponse("Username already exists", 400))
    }
  }
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create user", 500))
  }

  res.status(200).json({
    success: true,
    message: "User created successfully"
  })
})

// Create a group => /groupController/createGroup
exports.createGroup = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to create group
  const { group_name } = req.body

  //split group_name by comma
  const group_name_list = group_name.split(",")

  //Check if group already exists
  const [row, fields] = await connection.promise().query("SELECT * FROM usergroups WHERE group_name IN (?)", [group_name_list])
  if (row.length !== 0) {
    return next(new ErrorResponse("Group already exists", 400))
  }

  //Regex to check if group name is alphanumeric and no space
  const groupRegex = /^[a-zA-Z0-9]+$/
  for (let i = 0; i < group_name_list.length; i++) {
    if (!groupRegex.test(group_name_list[i])) {
      return next(new ErrorResponse("Group name must be alphanumeric and no space", 400))
    }
  }

  //Insert group into database one by one
  for (let i = 0; i < group_name_list.length; i++) {
    const result = await connection.promise().execute("INSERT INTO usergroups (group_name) VALUES (?)", [group_name_list[i]])

    //@TODO:
    if (result[0].affectedRows === 0) {
      return next(new ErrorResponse("Failed to create group", 500))
    }
  }

  res.status(200).json({
    success: true,
    message: "Group(s) created successfully"
  })
})

// Get all users => /userController/getUsers
exports.getUsers = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection.promise().query("SELECT username,email,group_list,is_disabled FROM user")
  res.status(200).json({
    success: true,
    data: rows
  })
})

// Get a user => /userController/getUser
exports.getUser = catchAsyncErrors(async (req, res, next) => {
  const username = req.user.username
  const [row, fields] = await connection.promise().query("SELECT username,email,group_list FROM user WHERE username = ?", [username])
  if (row.length === 0) {
    return next(new ErrorResponse("Invalid username or password", 404))
  }
  res.status(200).json({
    success: true,
    data: row[0]
  })
})

// Toggle user status => /userController/toggleUserStatus/:username
exports.toggleUserStatus = catchAsyncErrors(async (req, res, next) => {
  //Check if the user being updated is the root admin
  if (req.params.username === "admin") {
    //Don't even allow it
    return next(new ErrorResponse("Admin cannot be disabled", 403))
  }
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username])
  if (row.length === 0) {
    return next(new ErrorResponse("Invalid username or password", 404))
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
  //we need to check if the user being updated is the root admin
  if (req.params.username === "admin") {
    //only allow it if the requester is the root admin
    if (req.user.username !== "admin") {
      return next(new ErrorResponse("You are not authorised", 403))
    }
  }
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username])
  if (row.length === 0) {
    return next(new ErrorResponse("Invalid username or password", 404))
  }
  const user = row[0]
  //We need to check for password constraint, minimum character is 8 and maximum character is 10. It should include alphanumeric, number and special character. We do not care baout uppercase and lowercase.
  const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
  if (req.body.password && !passwordRegex.test(req.body.password)) {
    return next(new ErrorResponse("Password must be 8-10 characters long, contain at least one number, one letter and one special character", 400))
  }

  //the fields are optional to update, so we need to build the query dynamically
  let query = "UPDATE user SET "
  let values = []
  //Updatable fields are email, password, groups.
  if (req.body.email) {
    query += "email = ?, "
    values.push(req.body.email)
  } else if (req.body.email === undefined) {
    query += "email = ?, "
    values.push(null)
  }
  if (req.body.password) {
    query += "password = ?, "
    //bcrypt password with salt 10
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    values.push(hashedPassword)
  }
  if (req.body.group) {
    query += "`group_list` = ?, "
    values.push(req.body.group)
  }
  //group can be empty, if it is empty we should update the group_list to empty
  if (req.body.group === "") {
    query += "`group_list` = ?, "
    values.push("")
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
  const username = req.user.username
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username])
  if (row.length === 0) {
    return next(new ErrorResponse("Invalid username or password", 404))
  }

  const user = row[0]
  const result = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, username])
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
  const username = req.user.username
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username])
  if (row.length === 0) {
    return next(new ErrorResponse("Invalid username or password", 404))
  }

  const user = row[0]
  //password constraint check
  const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/
  if (!passwordRegex.test(req.body.password)) {
    return next(new ErrorResponse("Password must be 8-10 characters long, contain at least one number, one letter and one special character", 400))
  }

  //bcrypt new password with salt 10
  const hashedPassword = await bcrypt.hash(req.body.password, 10)

  const result = await connection.promise().execute("UPDATE user SET password = ? WHERE username = ?", [hashedPassword, username])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500))
  }

  sendToken(user, 200, res)
})

// Get all groups in usergroups table => /controller/getGroups
exports.getGroups = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection.promise().query("SELECT * FROM usergroups")
  if (rows.length === 0) {
    return next(new ErrorResponse("No groups found", 404))
  }
  res.status(200).json({
    success: true,
    data: rows
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

  res.status(statusCode).json({
    success: true,
    token,
    group_list: user.group_list,
    username: user.username
  })
}

const getJwtToken = user => {
  return jwt.sign({ username: user.username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_TIME
  })
}

/*
Assignment 2 stuff below, will be implementing the kanban board functionalities
*/

//Get all applications => /controller/getApplications
exports.getApplications = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection.promise().query("SELECT * FROM applications")
  res.status(200).json({
    success: true,
    data: rows
  })
})

/*
* createApplication => /controller/createApplication
* This function will create an application and insert it into the database.
* It will take in the following parameters:
* - App_Acronym (string) => acronym of the application
* - App_Description (string) => description of the application
* - App_Rnumber (string) => R number of the application
* - App_startDate (date), (optional) => start date of the application
* - App_endDate (date), (optional) => end date of the application
* - App_permit_Create (string), (optional) => permit create of the application
* - App_permit_Open (string), (optional) => permit open of the application
* - App_permit_toDoList (string), (optional) => permit toDoList of the application
* - App_permit_Doing (string), (optional) => permit doing of the application
* - App_permit_Done (string), (optional) => permit done of the application

* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Application already exists (400) => if the application already exists
* - Failed to create application (500) => if failed to create application

* It will also throw any other errors that are not caught

* This function is only accessible by users with the following roles:
* - admin
*/
exports.createApplication = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to create application
  const { App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_Create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done } = req.body

  //Check if required parameters are provided
  if (!App_Acronym || !App_Description || !App_Rnumber) {
    return next(new ErrorResponse("Invalid input", 400))
  }

  //Check if application already exists
  const [row, fields] = await connection.promise().query("SELECT * FROM applications WHERE App_Acronym = ?", [App_Acronym])
  if (row.length !== 0) {
    return next(new ErrorResponse("Application already exists", 400))
  }

  //Insert application into database
  const result = await connection.promise().execute("INSERT INTO applications (App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_Create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done) VALUES (?,?,?,?,?,?,?,?,?,?)", [App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_Create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create application", 500))
  }

  res.status(200).json({
    success: true,
    message: "Application created successfully"
  })
})
