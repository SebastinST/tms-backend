const express = require('express');
const dotenv = require("dotenv");
const cors = require("cors");

/* 
To-do
- Handle missing optional fields for endpoints
- Find out what is CORS
- Checkgroup function
*/

//Setting up config.env file variable
dotenv.config({ path: "./config/config.env" });

//Setting up database connection
const connection = require("./config/database");

// Inititalize the app and add middleware
const app = express();
app.use(express.json());
app.use(cors());

//Importing routes
const router = require("./router")

//Mounting routes
app.use("/", router)

/** App listening on port */
const PORT = process.env.PORT
app.listen(PORT, () => {
  console.log(`TMS at http://localhost:${PORT}`);
});