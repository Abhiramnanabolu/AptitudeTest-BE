const express = require("express");
const cors = require("cors")
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const uuid = require("uuid").v4;
app.use(cors())
const dbPath = path.join(__dirname, "aptest.db");
const Port=process.env.PORT || 3111
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';


let db = null;

app.use(express.json());

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(Port, () => {
      console.log(`Server Running at http://localhost:${Port}/`);
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};
initializeDBAndServer();



app.get("/", async (req,res)=>{
    res.send("Its Working !!!!!!!!")
})

app.post("/signup", async (req, res) => {
    const { name, username, password } = req.body;
  
    // Basic validation
    if (!name || !username || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
  
    try {
      // Check if the username already exists
      const existingUser = await db.get("SELECT * FROM users WHERE username = ?", [username]);
      if (existingUser) {
        return res.status(400).json({ error: "Username already exists" });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Generate a UUID for the user ID
      const userId = uuid();
  
      // Insert the new user into the database
      const result = await db.run(
        "INSERT INTO users (id, name, username, password) VALUES (?, ?, ?, ?)",
        [userId, name, username, hashedPassword]
      );
  
      // Generate a JWT token
      const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '7d' });
  
      // Send success response with token
      res.status(201).json({ message: "User created successfully", token });
    } catch (error) {
      // Handle any errors
      console.error(`Error while signing up: ${error.message}`);
      res.status(500).json({ error: "Internal server error" });
    }
  });


  app.post("/signin", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" });
    }
  
    try {
      const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
      if (!user) {
        return res.status(401).json({ error: "Invalid username or password" });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
  
      if (!isMatch) {
        return res.status(401).json({ error: "Invalid username or password" });
      }
  
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  
      res.json({ token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get('/details', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Token required' });
  
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await db.get('SELECT username,name FROM users WHERE id = ?', [decoded.userId]);
  
      if (!user) return res.status(404).json({ error: 'User not found' });
  
      res.json(user);
    } catch (error) {
      res.status(403).json({ error: 'Invalid token' });
    }
  });

  app.get('/api/start-test/:category', async (req, res) => {
    const { category } = req.params;
    const authHeader = req.headers['authorization'];
  
    // Validate category
    if (!category) {
      return res.status(400).json({ error: "Category is required" });
    }
  
    // Check for authorization header
    if (!authHeader) {
      return res.status(401).json({ error: "Authorization token is required" });
    }
  
    const token = authHeader.split(' ')[1];
    
    try {
      // Verify the JWT token
      const decoded = jwt.verify(token, JWT_SECRET);
      const userId = decoded.userId;
  
      console.log("Start test request received");
      console.log("Category:", category);
      console.log("User ID:", userId);
  
      // Generate a unique test ID
      const testId = uuid();
      console.log("Generated Test ID:", testId);
      let questions;
      // Fetch 10 random questions for the given category
      if(category=="All-in-one"){
        questions = await db.all('SELECT * FROM questions ORDER BY RANDOM() LIMIT 10');
      }
      else{
        questions = await db.all('SELECT * FROM questions WHERE category = ? ORDER BY RANDOM() LIMIT 10', [category]);
      }
  
      if (questions.length === 0) {
        return res.status(404).json({ error: 'No questions found for this category' });
      }
      
      console.log(questions)
  
      // Insert the test entry into the tests table
      const result = await db.run('INSERT INTO tests (id, user_id, category, status) VALUES (?, ?, ?, ?)', [testId, userId, category, 'pending']);
      console.log("Test entry inserted:", result);
  
      // Insert each question ID into the test_questions table
      for (const question of questions) {
        await db.run('INSERT INTO test_questions (test_id, question_id) VALUES (?, ?)', [testId, question.id]);
      }
  
      console.log("Test ID and questions:", { testId, questions });
  
      // Send the test ID and questions as the response
      res.json({
        testId,
        questions
      });
    } catch (error) {
      console.error("Error while starting test:", error.message);
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({ error: 'Invalid token' });
      }
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/tests/submit', async (req, res) => {
    const { testId, score, timeTaken } = req.body;
  
    if (!testId || score === undefined || timeTaken === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
  
    try {
      const result = await db.get(
        'SELECT * FROM tests WHERE id = ?',
        [testId]
      );
  
      if (!result) {
        return res.status(404).json({ error: 'Test not found' });
      }
  
      const rr=await db.run(
        'UPDATE tests SET score = ?, timeTaken = ? WHERE id = ?',
        [score, timeTaken, testId]
      );
  
      res.status(200).json({ message: 'Test results updated successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  