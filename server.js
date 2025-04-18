const express = require("express")
const bodyParser = require("body-parser")
const cors = require("cors")
const fs = require("fs-extra")
const path = require("path")
const { OAuth2Client } = require("google-auth-library")

// Initialize Google OAuth client
const client = new OAuth2Client("741864469861-v3jmuek30cf8pvhdgd27d100nmpt4ot7.apps.googleusercontent.com")

// Create Express app
const app = express()
const PORT = process.env.PORT || 3000

// Middleware
app.use(cors())
app.use(bodyParser.json())
app.use(express.static(path.join(__dirname, ".")))

// Ensure data.json exists
const dataFile = path.join(__dirname, "data.json")
if (!fs.existsSync(dataFile)) {
  fs.writeJSONSync(dataFile, { users: [] })
}

// Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"))
})

// Login endpoint for Google OAuth
app.post("/login", async (req, res) => {
  const { username, email, avatar } = req.body

  try {
    // In a real implementation, you'd verify the Google token
    // const ticket = await client.verifyIdToken({
    //   idToken: token,
    //   audience: 'YOUR_GOOGLE_CLIENT_ID',
    // });
    // const payload = ticket.getPayload();

    // Load current users
    const data = fs.readJSONSync(dataFile)

    // Check if user already exists
    const existingUserIndex = data.users.findIndex((user) => user.email === email)

    if (existingUserIndex >= 0) {
      // Update existing user
      data.users[existingUserIndex] = {
        username,
        email,
        avatar,
        lastLogin: new Date().toISOString(),
      }
    } else {
      // Add new user
      data.users.push({
        username,
        email,
        avatar,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
      })
    }

    // Save data
    fs.writeJSONSync(dataFile, data)

    res.json({ success: true, message: "Login successful" })
  } catch (error) {
    console.error("Login error:", error)
    res.status(401).json({ success: false, message: "Authentication failed" })
  }
})

// Connect backend.js functionality
const backend = require("./backend.js")

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
