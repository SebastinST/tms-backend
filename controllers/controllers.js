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
* - App_Rnumber (int) => R number of the application
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
  let { App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_Create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done } = req.body

  //Check if any of the required parameters are not provided
  if (!App_Acronym || !App_Description || !App_Rnumber) {
    return next(new ErrorResponse("Invalid input", 400))
  }

  //Check if application already exists
  const [row, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
  if (row.length !== 0) {
    return next(new ErrorResponse("Application already exists", 400))
  }

  //App_Rnumber constraints: Must not be negative and must not be a float.
  if (App_Rnumber < 0 || App_Rnumber % 1 !== 0) {
    return next(new ErrorResponse("Invalid input", 400))
  }

  //We need to handle the optional parameters, if they are not provided, we will set them to null
  if (!App_startDate) {
    App_startDate = null
  }
  if (!App_endDate) {
    App_endDate = null
  }
  if (!App_permit_Create) {
    App_permit_Create = null
  }
  if (!App_permit_Open) {
    App_permit_Open = null
  }
  if (!App_permit_toDoList) {
    App_permit_toDoList = null
  }
  if (!App_permit_Doing) {
    App_permit_Doing = null
  }
  if (!App_permit_Done) {
    App_permit_Done = null
  }

  //Insert application into database
  const result = await connection.promise().execute("INSERT INTO application (App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_Create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done) VALUES (?,?,?,?,?,?,?,?,?,?)", [App_Acronym, App_Description, App_Rnumber, App_startDate, App_endDate, App_permit_Create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create application", 500))
  }

  res.status(200).json({
    success: true,
    message: "Application created successfully"
  })
})

/*
* updateApplication => /controller/updateApplication/:App_Acronym
* This function will update an application and insert it into the database.
* It will take in the following parameters:
* - App_Description (string), (optional) => description of the application
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
* - Application does not exist (404) => if the application does not exist
* - Failed to update application (500) => if failed to update application

* It will also throw any other errors that are not caught

* This function is only accessible by users with the following roles:
* - admin
*/
exports.updateApplication = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to update application
  const App_Acronym = req.params.App_Acronym
  const [row, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
  if (row.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }

  //Since all the parameters are optional, we need to build the query dynamically, if the parameter is not provided, we will not update it
  let query = "UPDATE application SET "
  let values = []
  if (req.body.App_Description) {
    query += "App_Description = ?, "
    values.push(req.body.App_Description)
  }
  if (req.body.App_startDate) {
    query += "App_startDate = ?, "
    values.push(req.body.App_startDate)
  }
  if (req.body.App_endDate) {
    query += "App_endDate = ?, "
    values.push(req.body.App_endDate)
  }
  if (req.body.App_permit_Create) {
    query += "App_permit_Create = ?, "
    values.push(req.body.App_permit_Create)
  }
  if (req.body.App_permit_Open) {
    query += "App_permit_Open = ?, "
    values.push(req.body.App_permit_Open)
  }
  if (req.body.App_permit_toDoList) {
    query += "App_permit_toDoList = ?, "
    values.push(req.body.App_permit_toDoList)
  }
  if (req.body.App_permit_Doing) {
    query += "App_permit_Doing = ?, "
    values.push(req.body.App_permit_Doing)
  }
  if (req.body.App_permit_Done) {
    query += "App_permit_Done = ?, "
    values.push(req.body.App_permit_Done)
  }
  //remove the last comma and space
  query = query.slice(0, -2)
  //add the where clause
  query += " WHERE App_Acronym = ?"
  values.push(App_Acronym)
  const result = await connection.promise().execute(query, values)
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update application", 500))
  }

  res.status(200).json({
    success: true,
    message: "Application updated successfully"
  })
})

/*
* getApplication => /controller/getApplication/:App_Acronym
* This function will get an application from the database.
* It will take in the following parameters:
* - App_Acronym (string) => acronym of the application

* It will return the following:
* - success (boolean) => true if successful, false if not
* - data (object) => the application object

* It will throw the following errors:
* - Application does not exist (404) => if the application does not exist

* It will also throw any other errors that are not caught

* This function is only accessible by users with the following roles:
* - admin
*/

exports.getApplication = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to get application
  const App_Acronym = req.params.App_Acronym
  const [row, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
  if (row.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }
  res.status(200).json({
    success: true,
    data: row[0]
  })
})

/*
* getTasks => /controller/getTasks
* This function will get all tasks from the database.

* It will return the following:
* - success (boolean) => true if successful, false if not
* - data (array) => the tasks array

* It will throw the following errors:
* - No tasks found (404) => if no tasks are found

* It will also throw any other errors that are not caught
*/

exports.getTasks = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection.promise().query("SELECT * FROM task")
  if (rows.length === 0) {
    return next(new ErrorResponse("No tasks found", 404))
  }
  res.status(200).json({
    success: true,
    data: rows
  })
})

/*
* getTasksByApp => /controller/getTasksByApp/:App_Acronym
* This function will get all tasks from the database that belongs to an application.
* It will take in the following parameters:
* - App_Acronym (string) => acronym of the application

* It will return the following:
* - success (boolean) => true if successful, false if not
* - data (array) => the tasks array

* It will throw the following errors:
* - No tasks found (404) => if no tasks are found
* - Application does not exist (404) => if the application does not exist

* It will also throw any other errors that are not caught
*/
exports.getTasksByApp = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to get tasks
  const App_Acronym = req.params.App_Acronym
  const [row, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
  if (row.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }
  const application = row[0]
  const [row2, fields2] = await connection.promise().query("SELECT * FROM task WHERE Task_app_acronym = ?", [App_Acronym])
  if (row2.length === 0) {
    return next(new ErrorResponse("No tasks found", 404))
  }
  res.status(200).json({
    success: true,
    data: row2
  })
})

/*
* createTask => /controller/createTask
* This function will create a task and insert it into the database.
* It will take in the following parameters:
* - Task_name (string) => name of the task
* - Task_description (string), (optional) => description of the task
* - Task_notes (string), (optional) => notes of the task
* - Task_id (string), (generated) => id of the task, this is the primary key. This is a combination of the application acronym and the application R number. 
    Take in App_Acronym as a parameter and get the R number from the application table then generate the Task_id
* - Task_plan (string), (optional) => plan of the task
* - Task_app_acronym (string), (generated) => acronym of the application that the task belongs to
* - Task_state (string), (generated) => state of the task, default to open.
* - Task_creator (string), (generated) => creator of the task, default to current user's username
* - Task_owner (string), (generated) => owner of the task, default to current user's username
* - Task_createDate (date), (generated) => create date of the task, default to current date
 
* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Failed to create task (500) => if failed to create task

* It will also throw any other errors that are not caught

* This function is only accessible by users with the following roles:
* - admin
* - projectlead
*/
exports.createTask = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to create task
  let { Task_name, Task_description, Task_notes, Task_plan, Task_app_acronym } = req.body
  let user = req.user.username

  //Check if any of the required parameters are not provided
  if (!Task_name || !Task_app_acronym) {
    return next(new ErrorResponse("Invalid input", 400))
  }

  //We need to handle the optional parameters, if they are not provided, we will set them to null
  if (!Task_description) {
    Task_description = null
  }
  if (!Task_notes) {
    Task_notes = null
  }
  if (!Task_plan) {
    Task_plan = null
  }

  //Generate Task_id
  const [row, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Task_app_acronym])
  if (row.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }

  const application = row[0]
  const Task_id = Task_app_acronym + application.App_Rnumber

  //Generate Task_app_acronym
  Task_app_acronym = application.App_Acronym

  //Generate Task_state
  const Task_state = "Open"

  //Generate Task_creator
  const Task_creator = user

  //Generate Task_owner
  const Task_owner = user

  //Generate Task_createDate, the date is in the format YYYY-MM-DD HH:MM:SS. This is using current local time
  const Task_createDate = new Date().toISOString().slice(0, 19).replace("T", " ")
  //@TODO make it use local timezone.
  console.log(Task_createDate)

  //Insert task into database
  const result = await connection.promise().execute("INSERT INTO task (Task_name, Task_description, Task_notes, Task_id, Task_plan, Task_app_acronym, Task_state, Task_creator, Task_owner, Task_createDate) VALUES (?,?,?,?,?,?,?,?,?,?)", [Task_name, Task_description, Task_notes, Task_id, Task_plan, Task_app_acronym, Task_state, Task_creator, Task_owner, Task_createDate])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create task", 500))
  }

  //Increment the application R number
  const newApp_Rnumber = application.App_Rnumber + 1
  const result2 = await connection.promise().execute("UPDATE application SET App_Rnumber = ? WHERE App_Acronym = ?", [newApp_Rnumber, Task_app_acronym])
  if (result2[0].affectedRows === 0) {
    return next(new ErrorResponse("Something went wrong...", 500))
    //We should delete the task that was just created
  }
  res.status(200).json({
    success: true,
    message: "Task created successfully"
  })
})

/*
* getTask => /controller/getTask/:Task_id
* This function will get a task from the database.
* It will take in the following parameters:
* - Task_id (string) => id of the task

* It will return the following:
* - success (boolean) => true if successful, false if not
* - data (object) => the task object

* It will throw the following errors:
* - Task does not exist (404) => if the task does not exist

* It will also throw any other errors that are not caught

* This function is accessible by all users
*/
exports.getTask = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to get task
  const Task_id = req.params.Task_id
  const [row, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
  if (row.length === 0) {
    return next(new ErrorResponse("Task does not exist", 404))
  }
  res.status(200).json({
    success: true,
    data: row[0]
  })
})

/*
* updateNotes => /controller/updateNotes/:Task_id
* This function will update the notes of a task in the database.
* It will take in the following parameters:
* - Task_notes (string) => notes of the task

* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Task does not exist (404) => if the task does not exist
* - Failed to update notes (500) => if failed to update notes

* It will also throw any other errors that are not caught

* This function is accessible only by groups inside the permit of the task state.
*/
exports.updateNotes = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to update notes
  const Task_id = req.params.Task_id
  const [row, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
  if (row.length === 0) {
    return next(new ErrorResponse("Task does not exist", 404))
  }

  //Check if user is allowed to perform the action
  const validate = await validatePermit(row[0].Task_app_Acronym, row[0].Task_state, req.user.username)
  if (!validate) {
    return next(new ErrorResponse("You are not authorised", 403))
  }

  //Check if any of the required parameters are not provided
  if (!req.body.Task_notes) {
    return next(new ErrorResponse("Invalid input", 400))
  }

  //Update notes
  const result = await connection.promise().execute("UPDATE task SET Task_notes = ? WHERE Task_id = ?", [req.body.Task_notes, Task_id])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update notes", 500))
  }

  res.status(200).json({
    success: true,
    message: "Notes updated successfully"
  })
})

/*
* validatePermit => backend function to validate if the user is allowed to perform the action
* This function will take in the following parameters:
* - App_Acronym (string) => acronym of the application
* - Task_state (string) => state of the task
* - user (string) => username of the user

* It will return the following:
* - success (boolean) => true if successful, false if not

* It will throw the following errors:
* - Application does not exist (404) => if the application does not exist
* - Task does not exist (404) => if the task does not exist

* It will also throw any other errors that are not caught
*/
const validatePermit = catchAsyncErrors(async (App_Acronym, Task_state, user) => {
  //Check if application exists
  const [row, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
  if (row.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }

  //Check if user is allowed to perform the action
  const application = row[0]
  //Depending on the state, access the permit of the application
  let permit_state
  switch (Task_state) {
    case "Open":
      permit_state = application.App_permit_Open
      break
    case "ToDo":
      permit_state = application.App_permit_toDoList
      break
    case "Doing":
      permit_state = application.App_permit_Doing
      break
    case "Done":
      permit_state = application.App_permit_Done
      break
    default:
      return next(new ErrorResponse("Invalid task state", 400))
    //check permit if it is null
  }
  if (permit_state === null || permit_state === undefined) {
    return false
  }

  //Split the permit by comma
  const permit_list = permit_state.split(",")

  //Get user's groups
  const [row2, fields3] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [user])
  if (row2.length === 0) {
    return next(new ErrorResponse("User does not exist", 404))
  }

  //Get the user's groups
  const user_groups = row2[0].group_list.split(",")
  //Check if any of the user's groups is included in the permit array, then the user is authorized. The group has to match exactly
  //for each group in the group array, check match exact as group parameter
  authorised = false
  for (let i = 0; i < user_groups.length; i++) {
    if (permit_list.includes(user_groups[i])) {
      authorised = true
      break
    }
  }
  if (!authorised) {
    return false
  }
  return true
})

/*
* promoteTask => /controller/promoteTask/:Task_id
* This function will approve a task in the database and move it to the next state.
* It will take in the following parameters:
* - Task_notes (string) => notes of the task
* - Task_owner (string) => owner of the task. This is the username of the user that made the request
* - Task_state (string) => state of the task. This should be the current state of the task from the database
* - Task_id (string) => id of the task

* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Task does not exist (404) => if the task does not exist
* - You are not authorised (403) => if the user is not authorised to perform the action
* - Failed to promote task (500) => if failed to promote task

* It will also throw any other errors that are not caught

* This function is accessible only by groups inside the permit of the task state.
*/
exports.promoteTask = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to promote task
  const Task_id = req.params.Task_id
  const [row, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
  if (row.length === 0) {
    return next(new ErrorResponse("Task does not exist", 404))
  }

  //Check if user is allowed to perform the action
  const validate = await validatePermit(row[0].Task_app_Acronym, row[0].Task_state, req.user.username)
  if (!validate) {
    return next(new ErrorResponse("You are not authorised", 403))
  }

  //Get the current state of the task
  const Task_state = row[0].Task_state
  //Depending on the current state, we will update the state to the next state
  let nextState
  switch (Task_state) {
    case "Open":
      nextState = "ToDo"
      break
    case "ToDo":
      nextState = "Doing"
      break
    case "Doing":
      nextState = "Done"
      break
    case "Done":
      nextState = "Close"
      break
    default:
      nextState = "Close"
  }

  //Get the Task_owner from the req.user.username
  const Task_owner = req.user.username
  let Added_Task_notes
  if (req.body.Task_notes === undefined || null) {
    //append {Task_owner} moved {Task_name} from {Task_state} to {nextState} to the end of Task_note
    Added_Task_notes = Task_owner + " moved " + row[0].Task_name + " from " + Task_state + " to " + nextState
  } else {
    //Get the Task_notes from the req.body.Task_notes and append {Task_owner} moved {Task_name} from {Task_state} to {nextState} to the end of Task_note
    Added_Task_notes = req.body.Task_notes + "\n" + Task_owner + " moved " + row[0].Task_name + " from " + Task_state + " to " + nextState
  }

  //Append Task_notes to the preexisting Task_notes
  const Task_notes = Added_Task_notes + "\n" + row[0].Task_notes
  //Update the task
  const result = await connection.promise().execute("UPDATE task SET Task_notes = ?, Task_state = ?, Task_owner = ? WHERE Task_id = ?", [Task_notes, nextState, Task_owner, Task_id])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to promote task", 500))
  }

  res.status(200).json({
    success: true,
    message: "Task promoted successfully"
  })
})

/*
* rejectTask => /controller/rejectTask/:Task_id
* This function will reject a task in the database and move it back to the Doing state.
* It will take in the following parameters:
* - Task_notes (string) => notes of the task
* - Task_owner (string) => owner of the task. This is the username of the user that made the request
* - Task_state (string) => state of the task. This should be the current state of the task from the database
* - Task_id (string) => id of the task
* - Task_plan (string) => plan of the task.

* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Task does not exist (404) => if the task does not exist
* - You are not authorised (403) => if the user is not authorised to perform the action
* - Failed to reject task (500) => if failed to reject task

* It will also throw any other errors that are not caught

* This function is accessible only by groups inside the permit of the task state.
*/
exports.rejectTask = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to reject task
  const Task_id = req.params.Task_id
  const [row, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
  if (row.length === 0) {
    return next(new ErrorResponse("Task does not exist", 404))
  }

  //Check if user is allowed to perform the action
  const validate = await validatePermit(row[0].Task_app_Acronym, row[0].Task_state, req.user.username)
  if (!validate) {
    return next(new ErrorResponse("You are not authorised", 403))
  }

  //Get the current state of the task
  const Task_state = row[0].Task_state
  //If the current state is not Done, we cannot reject the task
  if (Task_state !== "Done") {
    return next(new ErrorResponse("You cannot reject a task that is not Done", 400))
  }
  //The state will always be Doing when rejecting a task
  const nextState = "Doing"

  //Get the Task_owner from the req.user.username
  const Task_owner = req.user.username
  let Added_Task_notes
  if (req.body.Task_notes === undefined || null) {
    //append {Task_owner} moved {Task_name} from {Task_state} to {nextState} to the end of Task_note
    Added_Task_notes = Task_owner + " moved " + row[0].Task_name + " from " + Task_state + " to " + nextState
  } else {
    //Get the Task_notes from the req.body.Task_notes and append {Task_owner} moved {Task_name} from {Task_state} to {nextState} to the end of Task_note
    Added_Task_notes = req.body.Task_notes + "\n" + Task_owner + " moved " + row[0].Task_name + " from " + Task_state + " to " + nextState
  }

  //Append Task_notes to the preexisting Task_notes
  const Task_notes = Added_Task_notes + "\n" + row[0].Task_notes

  //Task_plan can be updated if it is provided
  let Task_plan
  if (req.body.Task_plan === undefined || null) {
    Task_plan = row[0].Task_plan
  } else {
    Task_plan = req.body.Task_plan
  }

  //Update the task
  const result = await connection.promise().execute("UPDATE task SET Task_notes = ?, Task_state = ?, Task_owner = ?, Task_plan = ? WHERE Task_id = ?", [Task_notes, nextState, Task_owner, Task_plan, Task_id])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to reject task", 500))
  }

  res.status(200).json({
    success: true,
    message: "Task rejected successfully"
  })
})

/*
* returnTask => /controller/returnTask/:Task_id
* This function will demote a task in the database and move it back to the ToDo state.
* It will take in the following parameters:
* - Task_notes (string) => notes of the task
* - Task_owner (string) => owner of the task. This is the username of the user that made the request
* - Task_state (string) => state of the task. This should be the current state of the task from the database
* - Task_id (string) => id of the task

* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Task does not exist (404) => if the task does not exist
* - You are not authorised (403) => if the user is not authorised to perform the action
* - Failed to return task (500) => if failed to return task

* It will also throw any other errors that are not caught

* This function is accessible only by groups inside the permit of the task state.
*/
exports.returnTask = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to return task
  const Task_id = req.params.Task_id
  const [row, fields] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
  if (row.length === 0) {
    return next(new ErrorResponse("Task does not exist", 404))
  }

  //Check if user is allowed to perform the action
  const validate = await validatePermit(row[0].Task_app_Acronym, row[0].Task_state, req.user.username)
  if (!validate) {
    return next(new ErrorResponse("You are not authorised", 403))
  }

  //Get the current state of the task
  const Task_state = row[0].Task_state
  //If the current state is not Doing, we cannot return the task
  if (Task_state !== "Doing") {
    return next(new ErrorResponse("You cannot return a task that is not Doing", 400))
  }
  //The state will always be ToDo when returning a task
  const nextState = "ToDo"

  //Get the Task_owner from the req.user.username
  const Task_owner = req.user.username
  let Added_Task_notes
  if (req.body.Task_notes === undefined || null) {
    //append {Task_owner} moved {Task_name} from {Task_state} to {nextState} to the end of Task_note
    Added_Task_notes = Task_owner + " moved " + row[0].Task_name + " from " + Task_state + " to " + nextState
  } else {
    //Get the Task_notes from the req.body.Task_notes and append {Task_owner} moved {Task_name} from {Task_state} to {nextState} to the end of Task_note
    Added_Task_notes = req.body.Task_notes + "\n" + Task_owner + " moved " + row[0].Task_name + " from " + Task_state + " to " + nextState
  }

  //Append Task_notes to the preexisting Task_notes
  const Task_notes = Added_Task_notes + "\n" + row[0].Task_notes

  //Update the task
  const result = await connection.promise().execute("UPDATE task SET Task_notes = ?, Task_state = ?, Task_owner = ? WHERE Task_id = ?", [Task_notes, nextState, Task_owner, Task_id])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to return task", 500))
  }

  res.status(200).json({
    success: true,
    message: "Task returned successfully"
  })
})

/*
 * function to generate a random color hex code
 */
const getRandomColor = () => {
  const letters = "0123456789ABCDEF"
  let color = "#"
  for (let i = 0; i < 6; i++) {
    color += letters[Math.floor(Math.random() * 16)]
  }

  return color
}

/*
* getPlan => /controller/getPlan/
* This function will get the plan of a task from the database. As it is using a composite key of Plan_app_Acronym and Plan_MVP_name, we will need to get both of them from the req.body.
* It will take in the following parameters:
* - Plan_app_Acronym (string) => acronym of the application
* - Plan_MVP_name (string) => name of the MVP

* It will return the following:
* - success (boolean) => true if successful, false if not
* - data (object) => the plan object

* It will throw the following errors:
* - Plan does not exist (404) => if the plan does not exist

* It will also throw any other errors that are not caught

* This function is accessible only by users with the group "projectlead" in the application.
*/
exports.getPlan = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to get plan
  const { Plan_app_Acronym, Plan_MVP_name } = req.body
  const [row, fields] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?", [Plan_app_Acronym, Plan_MVP_name])
  if (row.length === 0) {
    return next(new ErrorResponse("Plan does not exist", 404))
  }
  res.status(200).json({
    success: true,
    data: row[0]
  })
})

/*
* getPlanByApp => /controller/getPlanByApp/:App_Acronym
* This function will get all plans of an application from the database.
* It will take in the following parameters:
* - App_Acronym (string) => acronym of the application

* It will return the following:
* - success (boolean) => true if successful, false if not
* - data (array) => the plans array

* It will throw the following errors:
* - No plans found (404) => if no plans are found
* - Application does not exist (404) => if the application does not exist

* It will also throw any other errors that are not caught

* This function is accessible only by users with the group "projectlead" in the application.
*/
exports.getPlanByApp = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to get plan
  const App_Acronym = req.params.App_Acronym
  const [row, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [App_Acronym])
  if (row.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }
  const application = row[0]
  const [row2, fields2] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ?", [App_Acronym])
  if (row2.length === 0) {
    return next(new ErrorResponse("No plans found", 404))
  }
  res.status(200).json({
    success: true,
    data: row2
  })
})

/*
* createPlan => /controller/createPlan
* This function will create a plan and insert it into the database.
* It will take in the following parameters:
* - Plan_app_Acronym (string) => acronym of the application
* - Plan_MVP_name (string) => name of the MVP
* - Plan_startDate (date), (optional) => start date of the plan
* - Plan_endDate (date), (optional) => end date of the plan
* - Plan_color (string), (optional) => color of the plan, default to random color

* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Plan already exists (400) => if the plan already exists
* - Application does not exist (404) => if the application does not exist
* - Failed to create plan (500) => if failed to create plan

* It will also throw any other errors that are not caught

* This function is accessible only by users with the group "projectlead" in the application.
*/
exports.createPlan = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to create plan
  const { Plan_app_Acronym, Plan_MVP_name } = req.body
  const [row, fields] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?", [Plan_app_Acronym, Plan_MVP_name])
  if (row.length !== 0) {
    return next(new ErrorResponse("Plan already exists", 400))
  }

  //Check if application exists
  const [row2, fields2] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Plan_app_Acronym])
  if (row2.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }

  //Check if any of the required parameters are not provided
  if (!Plan_app_Acronym || !Plan_MVP_name) {
    return next(new ErrorResponse("Invalid input", 400))
  }

  //We need to handle the optional parameters, if they are not provided, we will set them to null
  let { Plan_startDate, Plan_endDate, Plan_color } = req.body
  if (!Plan_startDate) {
    Plan_startDate = null
  }
  if (!Plan_endDate) {
    Plan_endDate = null
  }
  if (!Plan_color) {
    Plan_color = getRandomColor()
  }

  //Insert plan into database
  const result = await connection.promise().execute("INSERT INTO plan (Plan_app_Acronym, Plan_MVP_name, Plan_startDate, Plan_endDate, Plan_color) VALUES (?,?,?,?,?)", [Plan_app_Acronym, Plan_MVP_name, Plan_startDate, Plan_endDate, Plan_color])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create plan", 500))
  }

  res.status(200).json({
    success: true,
    message: "Plan created successfully"
  })
})

/*
* updatePlan => /controller/updatePlan/
* This function will update a plan in the database. Only the start date and end date can be updated.
* It will take in the following parameters:
* - Plan_app_Acronym (string) => acronym of the application
* - Plan_MVP_name (string) => name of the MVP
* - Plan_startDate (date), (optional) => start date of the plan
* - Plan_endDate (date), (optional) => end date of the plan

* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Plan does not exist (404) => if the plan does not exist
* - Application does not exist (404) => if the application does not exist
* - Failed to update plan (500) => if failed to update plan

* It will also throw any other errors that are not caught

* This function is accessible only by users with the group "projectlead" in the application.
*/
exports.updatePlan = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to update plan
  const { Plan_app_Acronym, Plan_MVP_name } = req.body
  const [row, fields] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?", [Plan_app_Acronym, Plan_MVP_name])
  if (row.length === 0) {
    return next(new ErrorResponse("Plan does not exist", 404))
  }

  //Check if application exists
  const [row2, fields2] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Plan_app_Acronym])
  if (row2.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }

  //Check if any of the required parameters are not provided
  if (!Plan_app_Acronym || !Plan_MVP_name) {
    return next(new ErrorResponse("Invalid input", 400))
  }

  //Since all the parameters are optional, we need to build the query dynamically, if the parameter is not provided, we will not update it
  let query = "UPDATE plan SET "
  let params = []
  if (req.body.Plan_startDate) {
    query += "Plan_startDate = ?,"
    params.push(req.body.Plan_startDate)
  }
  if (req.body.Plan_endDate) {
    query += "Plan_endDate = ?,"
    params.push(req.body.Plan_endDate)
  }
  //Remove the last comma
  query = query.slice(0, -1)
  //Add the WHERE clause
  query += " WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?"
  params.push(Plan_app_Acronym)
  params.push(Plan_MVP_name)

  //Update plan
  const result = await connection.promise().execute(query, params)
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update plan", 500))
  }

  res.status(200).json({
    success: true,
    message: "Plan updated successfully"
  })
})

/*
* assignTaskToPlan => /controller/assignTaskToPlan/:Task_id
* This function will assign a plan to a task in the database.
* It will take in the following parameters:
* - Task_id (string) => id of the task
* - Plan_app_Acronym (string) => acronym of the application
* - Plan_MVP_name (string) => name of the MVP
* - Task_notes (string) => notes of the task
* - Task_owner (string) => owner of the task. This is the username of the user that made the request

* It will return the following:
* - success (boolean) => true if successful, false if not
* - message (string) => message to be displayed

* It will throw the following errors:
* - Invalid input (400) => if any of the required parameters are not provided
* - Plan does not exist (404) => if the plan does not exist
* - Task does not exist (404) => if the task does not exist
* - Application does not exist (404) => if the application does not exist
* - Failed to assign plan to task (500) => if failed to assign plan to task

* It will also throw any other errors that are not caught

* This function is accessible only by users with the group "projectlead" in the application.
*/
exports.assignTaskToPlan = catchAsyncErrors(async (req, res, next) => {
  //Check if user is authorized to assign plan to task
  const { Plan_app_Acronym, Plan_MVP_name } = req.body
  const Task_id = req.params.Task_id
  const [row, fields] = await connection.promise().query("SELECT * FROM plan WHERE Plan_app_Acronym = ? AND Plan_MVP_name = ?", [Plan_app_Acronym, Plan_MVP_name])
  if (row.length === 0) {
    return next(new ErrorResponse("Plan does not exist", 404))
  }

  //Check if task exists
  const [row2, fields2] = await connection.promise().query("SELECT * FROM task WHERE Task_id = ?", [Task_id])
  if (row2.length === 0) {
    return next(new ErrorResponse("Task does not exist", 404))
  }

  //Check if application exists
  const [row3, fields3] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [Plan_app_Acronym])
  if (row3.length === 0) {
    return next(new ErrorResponse("Application does not exist", 404))
  }

  //Check if any of the required parameters are not provided
  if (!Plan_app_Acronym || !Plan_MVP_name) {
    return next(new ErrorResponse("Invalid input", 400))
  }

  //Get the Task_owner from the req.user.username
  const Task_owner = req.user.username
  let Added_Task_notes
  if (req.body.Task_notes === undefined || null) {
    //append {Task_owner} assigned {Task_name} to {Plan_MVP_name} to the end of Task_note
    Added_Task_notes = Task_owner + " assigned " + row2[0].Task_name + " to " + Plan_MVP_name
  } else {
    //Get the Task_notes from the req.body.Task_notes and append {Task_owner} assigned {Task_name} to {Plan_MVP_name} to the end of Task_note
    Added_Task_notes = req.body.Task_notes + "\n" + Task_owner + " assigned " + row2[0].Task_name + " to " + Plan_MVP_name
  }

  //Append Task_notes to the preexisting Task_notes
  const Task_notes = Added_Task_notes + "\n" + row2[0].Task_notes

  //Update the task including the task_owner
  const result = await connection.promise().execute("UPDATE task SET Task_notes = ?, Task_plan = ?, Task_owner = ? WHERE Task_id = ?", [Task_notes, Plan_MVP_name, Task_owner, Task_id])
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to assign plan to task", 500))
  }

  res.status(200).json({
    success: true,
    message: "Plan assigned to task successfully"
  })
})
