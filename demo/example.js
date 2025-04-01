// MongoDB Safe Queries Demo File
// This file demonstrates various MongoDB query patterns
// The extension will detect unsafe patterns in this file

const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const router = express.Router();

// Connection string - should be in environment variables in real applications
const uri =
  "mongodb+srv://username:password@cluster.mongodb.net/test?retryWrites=true&w=majority";
const client = new MongoClient(uri);

// Example route handling user search
router.get("/users", async (req, res) => {
  try {
    const db = client.db("testDB");
    const collection = db.collection("users");

    // UNSAFE: NoSQL Injection vulnerability using $where
    // This will be detected by the extension
    if (req.query.advancedSearch) {
      const results = await collection
        .find({
          $where: "this.username === '" + req.query.username + "'",
        })
        .toArray();
      return res.json(results);
    }

    // UNSAFE: Direct use of unvalidated user input
    // This will be detected by the extension
    if (req.query.username) {
      const results = await collection
        .find({
          username: req.query.username,
        })
        .toArray();
      return res.json(results);
    }

    // UNSAFE: Using regex with user input
    // This will be detected by the extension
    if (req.query.pattern) {
      const results = await collection
        .find({
          username: new RegExp(req.query.pattern),
        })
        .toArray();
      return res.json(results);
    }

    // UNSAFE: Unconstrained query
    // This will be detected by the extension
    const allUsers = await collection.find({}).toArray();
    return res.json(allUsers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Example route for updating user data
router.put("/users/:id", async (req, res) => {
  try {
    const db = client.db("testDB");
    const collection = db.collection("users");

    // UNSAFE: Using unvalidated ID
    // This will be detected by the extension
    const userId = req.params.id;

    // UNSAFE: Mass assignment vulnerability
    // This will be detected by the extension
    await collection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: req.body }
    );

    res.json({ message: "User updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Example route with pagination
router.get("/products", async (req, res) => {
  try {
    const db = client.db("testDB");
    const collection = db.collection("products");

    // UNSAFE: Uncontrolled limit
    // This will be detected by the extension
    const limit = parseInt(req.query.limit);

    // UNSAFE: Sort injection
    // This will be detected by the extension
    const sort = req.query.sort;

    const products = await collection
      .find({})
      .sort(sort)
      .limit(limit)
      .toArray();

    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SAFE alternatives below

// Safe user search with validation
router.get("/users/safe", async (req, res) => {
  try {
    const db = client.db("testDB");
    const collection = db.collection("users");

    // SAFE: Validated input
    let username = "";
    if (req.query.username && typeof req.query.username === "string") {
      username = req.query.username;
    }

    // SAFE: Specific query with validation
    const filter = { active: true };
    if (username) {
      filter.username = username;
    }

    // SAFE: Explicit projection (inclusion instead of exclusion)
    const projection = { username: 1, email: 1, createdAt: 1, _id: 1 };

    const results = await collection.find(filter).project(projection).toArray();

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Safe user update with validation
router.put("/users/:id/safe", async (req, res) => {
  try {
    const db = client.db("testDB");
    const collection = db.collection("users");

    // SAFE: Validated ObjectId
    const userId = req.params.id;
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    // SAFE: Explicit field selection instead of mass assignment
    const { name, email, role } = req.body;
    const updateData = {};

    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (role === "user" || role === "admin") updateData.role = role;

    await collection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: updateData }
    );

    res.json({ message: "User updated safely" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Safe product listing with controlled pagination
router.get("/products/safe", async (req, res) => {
  try {
    const db = client.db("testDB");
    const collection = db.collection("products");

    // SAFE: Controlled limit with fallback and upper bound
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 10, 1), 100);

    // SAFE: Whitelisted sort fields
    const allowedSortFields = ["name", "price", "createdAt"];
    const sortField = allowedSortFields.includes(req.query.sortField)
      ? req.query.sortField
      : "createdAt";

    const sortDir = req.query.sortDir === "desc" ? -1 : 1;

    const products = await collection
      .find({ active: true })
      .sort({ [sortField]: sortDir })
      .limit(limit)
      .toArray();

    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
