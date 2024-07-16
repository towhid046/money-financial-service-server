const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcrypt");
dotenv.config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.q1nysvk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const app = express();
const port = process.env.PORT || 3000;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Middleware to parse JSON requests
app.use(express.json());
app.use(cors({ origin: ["http://localhost:5173"] }));

app.get("/", (req, res) => {
  res.send("Mobile financial service is running...");
});

async function run() {
  try {
    const userCollections = client.db("MFS_DB").collection("users");

    app.post("/users", async (req, res) => {
      const user = req.body;
      const hashPassword = bcrypt.hashSync(user?.pin, 14);
      user.pin = hashPassword;
      user.role = "Pending";

      const isUserEmailExist = await userCollections.findOne({
        email: user.email,
      });
      if (isUserEmailExist) {
        return res
          .status(409)
          .send({ message: "User with this email address already exist!" });
      }

      const isUserMobileExist = await userCollections.findOne({
        mobile: user.mobile,
      });
      if (isUserMobileExist) {
        return res
          .status(409)
          .send({ message: "User with this phone number already exist!" });
      }
      const result = await userCollections.insertOne(user);
      res.send(result);
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// Start the server on port 3000
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
