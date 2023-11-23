const express = require("express")
const app = express()

const dotenv = require("dotenv")

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

/*const query = connection.query("SELECT * FROM user", function (error, result, fields) {
  console.log(result)
  console.log(fields)
})*/

//Setting up body parser
app.use(express.json())

//Importing routes
const auth = require("./routes/auth")

//Mounting routes
app.use("/api/v1/", auth)

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
