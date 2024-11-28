// server.js
const jsonServer = require("json-server");
const server = jsonServer.create();
const fs = require("fs");
const path = require("path");
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const SECRET_KEY = "your-secret-key";

// Initialize db.json if it doesn't exist
const dbFile = path.join(__dirname, "db.json");
if (!fs.existsSync(dbFile)) {
  fs.writeFileSync(
    dbFile,
    JSON.stringify({
      users: [],
      // other collections...
    })
  );
}

server.use(middlewares);
server.use(jsonServer.bodyParser);

// Register endpoint
server.post("/auth/register", async (req, res) => {
  console.log(req.body);
  try {
    const { email, password, name, school } = req.body;

    const db = router.db; // Access the lowdb instance
    const users = db.get("users");

    if (users.find({ email }).value()) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const user = {
      id: Date.now(),
      email,
      name,
      school,
      password: hashedPassword,
      role: "USER",
    };

    users.push(user).write();

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
      expiresIn: "2h",
    });
    // Send user data without password
    const userData = {
      id: user.id,
      email: user.email,
      name: user.name,
      school: user.school,
      role: user.role,
    };

    res.json({ token, user: userData });
  } catch (e) {
    console.log(e);
  }
});

// Login endpoint
server.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  const db = router.db;
  const user = db.get("users").find({ email }).value();

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
    expiresIn: "2h",
  });

  // Send user data without password
  const userData = {
    id: user.id,
    email: user.email,
    name: user.name,
    school: user.school,
    role: user.role,
  };

  res.json({ token, user: userData });
});

// Middleware to verify JWT
server.use((req, res, next) => {
  if (req.path === "/auth/login" || req.path === "/auth/register")
    return next();

  const authHeader = req.headers.authorization;
  console.log(authHeader);
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing token" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// Use router after middleware
server.use(router);

server.listen(4000, "0.0.0.0", () => {
  console.log("Server running on port 4000");
});
