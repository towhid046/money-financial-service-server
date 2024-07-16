const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
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
app.use(cookieParser());
app.use(cors({ origin: ["http://localhost:5173"], credentials: true }));

app.get("/", (req, res) => {
  res.send("Mobile financial service is running...");
});

async function run() {
  try {
    const userCollections = client.db("MFS_DB").collection("users");
    const transactionCollections = client
      .db("MFS_DB")
      .collection("transactions");

    // --------------------------------------------------
    // jwt related api:

    app.post("/jwt", async (req, res) => {
      const email = req.body;
      const token = jwt.sign(email, process.env.USER_TOKEN_SECRET, {
        expiresIn: "7h", // Correct format using 'h' for hours
      });

      // Assuming cookieOptions is defined elsewhere
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true, token });
    });

    // ---------------------------------------------------
    // user registration and login related apis:
    app.post("/users", async (req, res) => {
      const user = req.body;
      const hashPassword = bcrypt.hashSync(user?.pin, 14);

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
      const result = await userCollections.insertOne({
        ...user,
        pin: hashPassword,
        status: "Pending",
      });
      res.send(result);
    });

    // get a single user by mobile and password: for login:
    app.get("/user-login", async (req, res) => {
      const { mobile, pin } = req?.query;
      const user = await userCollections.findOne({ mobile });
      if (!user) {
        return res.status(404).send({ message: "User Not found" });
      }
      const isMatch = bcrypt.compareSync(pin, user.pin);
      if (!isMatch) {
        return res.status(409).send({ message: "Password not match" });
      }
      if (isMatch) {
        return res.send(user);
      }
    });

    // ---------------------------------------------------
    // get all users:
    app.get("/users", async (req, res) => {
      const result = await userCollections.find().toArray();
      res.send(result);
    });

    // approve (update) a user by admin:
    app.put("/activate-user", async (req, res) => {
      const email = req.query?.email;
      const role = req.query?.role;
      const user = await userCollections.findOne({ email, applyFor: role });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }
      const updateDoc = {
        $set: {
          role: user.applyFor,
          status: "Active",
          bonus: user.bonus
            ? user.bonus
            : user.applyFor === "Agent"
            ? 10000
            : 40,
          total:
            user.total || user.bonus
              ? user.total
              : user.applyFor === "Agent"
              ? 10000
              : 40,
        },
      };

      const result = await userCollections.updateOne({ email }, updateDoc);

      res.send(result);
    });

    // Blocked a user:
    app.patch("/blocked-user", async (req, res) => {
      const email = req.query?.email;
      const user = await userCollections.findOne({ email });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }
      const updateDoc = {
        $set: {
          role: false,
          status: "Blocked",
        },
      };
      const result = await userCollections.updateOne({ email }, updateDoc);
      res.send(result);
    });
    // --------------------------------------------------
    app.get("/single-user", async (req, res) => {
      const email = req.query?.email;
      if (!email) {
        return res.send({ message: "Email is required!" });
      }
      const user = await userCollections.findOne({ email });
      res.send(user);
    });
    // -------------------------------------------------
    app.post("/transaction", async (req, res) => {
      const { from, pin, userNumber, amount } = req.body;
      const user = await userCollections.findOne({ mobile: from });
      if (!user) {
        return res.status(409).send({ message: "You are not a valid user" });
      }
      const isMatch = bcrypt.compareSync(pin, user.pin);
      if (!isMatch) {
        return res.status(409).send({ message: "Invalid Pin Number" });
      }

      const toUser = await userCollections.findOne({ mobile: userNumber });
      if (!toUser) {
        return res.status(409).send({ message: "User number is Invalid" });
      }

      if (toUser.status === "Pending") {
        return res.status(409).send({
          message: "User Number is status is Pending for registration",
        });
      }

      if (Number(amount) > Number(user.total)) {
        return res
          .status(409)
          .send({ message: "You do not have enough balance" });
      }
      // calculate the money:

      const updateFromUserDoc = {
        $set: {
          total:
            Number(amount) > 100
              ? Number(user.total) - (Number(amount) + 5)
              : Number(user.total) - Number(amount),
        },
      };
      await userCollections.updateOne({ mobile: from }, updateFromUserDoc);
      const updateToUserDoc = {
        $set: { total: Number(toUser.total) + Number(amount) },
      };
      await userCollections.updateOne({ mobile: userNumber }, updateToUserDoc);

      const result = await transactionCollections.insertOne(req?.body);
      res.send(result);
    });

    // -------------------------------------------------
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
