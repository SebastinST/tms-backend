const express = require("express")
const cors = require("cors")
const app = express()
app.use(cors())

const dotenv = require("dotenv")
//const cookieParser = require("cookie-parser")

//Setting up config.env file variable
dotenv.config({ path: "./config/config.env" })

//Handle uncaught exceptions
process.on("uncaughtException", err => {
  console.log(`ERROR: ${err.stack}`)
  console.log("Shutting down due to uncaught exception")
  process.exit(1)
})

//Setting up database connection
const connection = require("./config/database")
const errorMiddleware = require("./middleware/errors")
const ErrorHandler = require("./utils/errorHandler")

//Setting up body parser
app.use(express.json())

//Setting up cookie parser
//app.use(cookieParser())

//Importing routes
const auth = require("./routes/auth")
const user = require("./routes/user")
const routes = require("./routes/routes")

//Mounting routes
app.use("/", auth)
app.use("/userController", user)
app.use("/controller", routes)

//Handle unhandled routes
app.all("*", (req, res, next) => {
  res.status(404).json({
    success: false,
    message: "Page not found"
  })
})

//Middleware to handle errors
app.use(errorMiddleware)

const PORT = process.env.PORT
const server = app.listen(PORT, () => {
  console.log(`Server started on port ${PORT} in ${process.env.NODE_ENV} mode`)
})

//Handle unhandled promise rejections
process.on("unhandledRejection", err => {
  console.log(`ERROR: ${err.stack}`)
  console.log("Shutting down the server due to unhandled promise rejection")
  server.close(() => {
    process.exit(1)
  })
})
