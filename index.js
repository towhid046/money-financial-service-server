const express = require("express");
const dotenv = require("dotenv");
dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON requests
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Mobile financial service is running...");
});

// Start the server on port 3000
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
