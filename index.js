const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
dotenv.config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
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
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
      "https://money-management-system-12c4f.web.app",
    ],
    credentials: true,
  })
);

app.get("/", (req, res) => {
  res.send("Mobile financial service is running...");
});

async function run() {
  try {
    const userCollections = client.db("MFS_DB").collection("users");
    const transactionCollections = client
      .db("MFS_DB")
      .collection("transactions");
    const requestedTransactionCollections = client
      .db("MFS_DB")
      .collection("requested_transactions");

    // --------------------------------------
    // token verification related apis:
    const verifyToken = async (req, res, next) => {
      const token = req.cookies.token;
      if (!token) {
        return res.status(401).send("not authorize");
      }
      jwt.verify(token, process.env.USER_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send("not authorize");
        }
        req.user = decoded;
        next();
      });
    };

    // verify  admin middleware:
    const verifyAdmin = async (req, res, next) => {
      const email = req?.user?.email;
      const user = await userCollections.findOne(
        { email },
        { projection: { _id: 0, role: 1 } }
      );
      if (user.role !== "Admin") {
        return res.status(403).send({ message: "Forbidden access" });
      }
      next();
    };

    // -------------------------------------------------
    app.get("/get-user-role/:email", verifyToken, async (req, res) => {
      const email = req?.params?.email;
      if (email !== req.user.email) {
        return res.status(403).send({ message: "Forbidden Access" });
      }
      const user = await userCollections.findOne(
        { email },
        { projection: { _id: 0, role: 1 } }
      );
      res.send({ role: user.role });
    });
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

    app.post("/logout", async (req, res) => {
      res
        .clearCookie("token", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          maxAge: 0,
        })
        .send({ success: true });
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
        return res.status(409).send({ message: "Pin not match" });
      }
      if (isMatch) {
        return res.send(user);
      }
    });

    // ---------------------------------------------------
    // get all users:
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await userCollections.find().toArray();
      res.send(result);
    });

    // approve (update) a user by admin:
    app.put("/activate-user", verifyToken, verifyAdmin, async (req, res) => {
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
    app.patch("/blocked-user", verifyToken, verifyAdmin, async (req, res) => {
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
    // send money related apis:
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

      const transaction = req?.body;
      delete transaction.pin;
      const result = await transactionCollections.insertOne(transaction);
      res.send(result);
    });
    // -------------------------------------------------
    // get all transactions:
    app.get("/transactions", verifyToken, verifyAdmin, async (req, res) => {
      const result = await transactionCollections.find().toArray();
      res.send(result);
    });

    // get all specific transactions by user mobile:
    app.get("/specific-transactions", verifyToken, async (req, res) => {
      const mobile = req.query?.mobile;
      const result = await transactionCollections
        .find({ from: mobile })
        .toArray();

      const result2 = await transactionCollections
        .find({ userNumber: mobile })
        .toArray();
      res.send([...result, ...result2]);
    });
    // ----------------------------------------------------
    // cash in related apis:
    app.post("/requested-transaction-cash-in", async (req, res) => {
      const { from } = req.body;
      const isAgent = await userCollections.findOne({
        mobile: from,
        role: "Agent",
      });
      if (!isAgent) {
        return res
          .status(409)
          .send({ message: "This is not a valid agent number" });
      }
      const result = await requestedTransactionCollections.insertOne(req.body);
      res.send(result);
    });

    // cash out related apis
    app.post("/requested-transaction-cash-out", async (req, res) => {
      const { from, pin, amount, userNumber } = req.body;
      const user = await userCollections.findOne({ mobile: from });

      if (!user) {
        return res.status(409).send({ message: "User not fond" });
      }
      const isPinMatch = bcrypt.compareSync(pin, user.pin);

      if (!isPinMatch) {
        return res.status(409).send({ message: "You pin not match" });
      }

      if (Number(user.total) < Number(amount)) {
        return res.status(409).send({
          message: "You do not have sufficient balance to cash out",
        });
      }
      const isAgent = await userCollections.findOne({
        mobile: userNumber,
        role: "Agent",
      });
      if (!isAgent) {
        return res
          .status(409)
          .send({ message: "This is not a valid agent number" });
      }
      const resp = await userCollections.updateOne(
        { _id: new Object(user._id) },
        { $set: { total: Number(user.total) - Number(amount) } }
      );
      if (resp.modifiedCount) {
        const result = await requestedTransactionCollections.insertOne(
          req.body
        );
        return res.send(result);
      }
    });

    // get all requested transactions:
    app.get("/requested-transactions", async (req, res) => {
      try {
        const result = await requestedTransactionCollections.find().toArray();
        res.send(result);
      } catch (error) {
        res.send(error);
      }
    });
    // -----------------------------------------------------
    // approve the cash in or cash out related apis:
    app.post("/approve-transaction", async (req, res) => {
      const id = req.query?.id;
      const filter = { _id: new ObjectId(id) };
      const transaction = await requestedTransactionCollections.findOne(filter);
      if (!transaction) {
        return res.status(400).send({ message: "Something went wrong!" });
      }
      if (transaction.type === "Cash In") {
        const user = await userCollections.findOne({
          mobile: transaction.userNumber,
          role: "User",
        });
        const agent = await userCollections.findOne({
          mobile: transaction.from,
          role: "Agent",
        });
        if (!user || !agent) {
          return res.status(401).send({ message: "Something went wrong!" });
        }
        const userDoc = {
          $set: { total: Number(user.total) + Number(transaction.amount) },
        };
        const agentDoc = {
          $set: { total: Number(agent.total) - Number(transaction.amount) },
        };
        await userCollections.updateOne({ mobile: user.mobile }, userDoc);
        await userCollections.updateOne({ mobile: agent.mobile }, agentDoc);

        delete transaction._id;
        const resp = await transactionCollections.insertOne(transaction);
        if (resp.insertedId) {
          const result = await requestedTransactionCollections.deleteOne(
            filter
          );
          return res.send(result);
        }
      }

      // ----------------------------------------
      // Cash out transaction

      if (transaction.type === "Cash Out") {
        const user = await userCollections.findOne({
          mobile: transaction.from,
          role: "User",
        });
        const agent = await userCollections.findOne({
          mobile: transaction.userNumber,
          role: "Agent",
        });
        const userDoc = {
          $set: { total: Number(user.total) - Number(transaction.amount) },
        };
        const agentDoc = {
          $set: { total: Number(agent.total) + Number(transaction.amount) },
        };
        await userCollections.updateOne({ mobile: user.mobile }, userDoc);
        await userCollections.updateOne({ mobile: agent.mobile }, agentDoc);

        delete transaction._id;
        const resp = await transactionCollections.insertOne(transaction);
        if (resp.insertedId) {
          const result = await requestedTransactionCollections.deleteOne(
            filter
          );
          return res.send(result);
        }
      }
    });
    // -----------------------------------------------------
    // decline the transaction request
    app.delete("/delete-transaction", async (req, res) => {
      const id = req.query?.id;
      const filter = { _id: new ObjectId(id) };
      const mobile = req.query?.mobile;

      const user = await userCollections.findOne({ mobile });
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      const { amount } = await requestedTransactionCollections.findOne(filter, {
        projection: { _id: 0, amount: 1 },
      });
      const resp = await userCollections.updateOne(
        { mobile },
        { $set: { total: Number(user.total) + Number(amount) } }
      );

      if (resp.modifiedCount) {
        const result = await requestedTransactionCollections.deleteOne(filter);
        return res.send(result);
      }
    });
    // -----------------------------------------------------
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
