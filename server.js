const express = require("express")
const bodyParser = require("body-parser")
const cors = require("cors")
const fs = require("fs-extra")
const path = require("path")
const { OAuth2Client } = require("google-auth-library")
const dotenv = require("dotenv")
const crypto = require("crypto")
const jwt = require("jsonwebtoken")
const Pusher = require("pusher")
const { Pool } = require("pg")
const requestIp = require("request-ip")
const cookieParser = require("cookie-parser")

dotenv.config()

// Import custom JS files
try {
  const matchmaking = require("./matchmaking.js")

  // Initialize matchmaking module if it has init function
  if (typeof matchmaking.init === "function") {
    matchmaking.init()
  }

  console.log("Successfully loaded matchmaking module")
} catch (error) {
  console.error("Error loading matchmaking module:", error)
}

// Initialize express app
const app = express()
const PORT = process.env.PORT || 3000

// Google OAuth configuration
const GOOGLE_CLIENT_ID = "741864469861-v3jmuek30cf8pvhdgd27d100nmpt4ot7.apps.googleusercontent.com"
const GOOGLE_CLIENT_SECRET = "GOCSPX-Ow-Iy-Iy-Iy-Iy-Iy-Iy-Iy-Iy-Iy-Iy" // Replace with your actual client secret
const JWT_SECRET = "diplomaq-secret-key" // Replace with a strong secret in production
const REDIRECT_URI = "https://diplomaq-production.up.railway.app/api/auth/callback/google"
const FRONTEND_URL = "https://diplomaq-production.up.railway.app"

// Admin emails with ban permissions
const ADMIN_EMAILS = ["alexandroghanem@gmail.com", "alexandroghanem1@gmail.com"]

// Initialize Google OAuth2 client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI)

// Initialize Pusher
const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID || "1723394",
  key: process.env.PUSHER_KEY || "6a59bdd1f5df05fd2554",
  secret: process.env.PUSHER_SECRET || "a7a5c1c3a6a1a1a1a1a1",
  cluster: process.env.PUSHER_CLUSTER || "eu",
  useTLS: true,
})

// Initialize PostgreSQL connection (if available)
let pool
try {
  if (process.env.DATABASE_URL) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
    console.log("PostgreSQL connection initialized")
  }
} catch (error) {
  console.error("Error initializing PostgreSQL:", error)
}

// Middleware
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cors())
app.use(requestIp.mw()) // Add IP detection middleware
app.use(cookieParser()) // Add cookie parser middleware

// Serve static files from the root directory
app.use(express.static("./"))

// Data storage paths
const DATA_FILE = path.join(__dirname, "data.json")
const DEBATES_FILE = path.join(__dirname, "debates.json")
const MESSAGES_FILE = path.join(__dirname, "messages.json")
const BANS_FILE = path.join(__dirname, "bans.json")
const MATCHMAKING_FILE = path.join(__dirname, "matchmaking.json")

// Initialize data files if they don't exist
if (!fs.existsSync(DATA_FILE)) {
  fs.writeJsonSync(DATA_FILE, { users: [] })
}

if (!fs.existsSync(DEBATES_FILE)) {
  fs.writeJsonSync(DEBATES_FILE, {
    debates: [
      {
        id: "1",
        title: "Climate Change Solutions",
        description: "Discussing effective policies to combat climate change",
        council: "UNEP",
        status: "active",
        participants: [],
        createdAt: new Date().toISOString(),
        startTime: new Date().toISOString(),
        endTime: null,
      },
      {
        id: "2",
        title: "Global Health Crisis Response",
        description: "Strategies for international cooperation during health emergencies",
        council: "WHO",
        status: "active",
        participants: [],
        createdAt: new Date().toISOString(),
        startTime: new Date().toISOString(),
        endTime: null,
      },
      {
        id: "3",
        title: "Nuclear Disarmament",
        description: "Discussing the path to global nuclear disarmament",
        council: "UNSC",
        status: "active",
        participants: [],
        createdAt: new Date().toISOString(),
        startTime: new Date().toISOString(),
        endTime: null,
      },
      {
        id: "4",
        title: "Refugee Crisis Management",
        description: "Addressing the global refugee crisis and humanitarian response",
        council: "UNHRC",
        status: "active",
        participants: [],
        createdAt: new Date().toISOString(),
        startTime: new Date().toISOString(),
        endTime: null,
      },
      {
        id: "5",
        title: "Sustainable Development Goals",
        description: "Progress and challenges in achieving the UN SDGs",
        council: "ECOSOC",
        status: "scheduled",
        participants: [],
        createdAt: new Date().toISOString(),
        startTime: new Date(Date.now() + 86400000).toISOString(), // Tomorrow
        endTime: null,
      },
    ],
  })
}

if (!fs.existsSync(MESSAGES_FILE)) {
  fs.writeJsonSync(MESSAGES_FILE, { messages: [] })
}

if (!fs.existsSync(BANS_FILE)) {
  fs.writeJsonSync(BANS_FILE, { bans: [] })
}

if (!fs.existsSync(MATCHMAKING_FILE)) {
  fs.writeJsonSync(MATCHMAKING_FILE, {
    queue: [],
    matches: [],
  })
}

// Helper functions
const readData = () => {
  try {
    return fs.readJsonSync(DATA_FILE)
  } catch (error) {
    console.error("Error reading data file:", error)
    return { users: [] }
  }
}

const writeData = (data) => {
  try {
    fs.writeJsonSync(DATA_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to data file:", error)
    return false
  }
}

const readDebates = () => {
  try {
    return fs.readJsonSync(DEBATES_FILE)
  } catch (error) {
    console.error("Error reading debates file:", error)
    return { debates: [] }
  }
}

const writeDebates = (data) => {
  try {
    fs.writeJsonSync(DEBATES_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to debates file:", error)
    return false
  }
}

const readMessages = () => {
  try {
    return fs.readJsonSync(MESSAGES_FILE)
  } catch (error) {
    console.error("Error reading messages file:", error)
    return { messages: [] }
  }
}

const writeMessages = (data) => {
  try {
    fs.writeJsonSync(MESSAGES_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to messages file:", error)
    return false
  }
}

const readBans = () => {
  try {
    return fs.readJsonSync(BANS_FILE)
  } catch (error) {
    console.error("Error reading bans file:", error)
    return { bans: [] }
  }
}

const writeBans = (data) => {
  try {
    fs.writeJsonSync(BANS_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to bans file:", error)
    return false
  }
}

const readMatchmaking = () => {
  try {
    return fs.readJsonSync(MATCHMAKING_FILE)
  } catch (error) {
    console.error("Error reading matchmaking file:", error)
    return { queue: [], matches: [] }
  }
}

const writeMatchmaking = (data) => {
  try {
    fs.writeJsonSync(MATCHMAKING_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to matchmaking file:", error)
    return false
  }
}

// Ban management functions
const isUserBanned = (email, ip) => {
  const bansData = readBans()
  const now = new Date()

  // Filter active bans for this email or IP
  const activeBans = bansData.bans.filter((ban) => {
    // Check if ban is still active based on duration
    if (ban.permanent) return true
    if (ban.expiresAt && new Date(ban.expiresAt) > now) {
      // Ban is still active, check if it matches email or IP
      return ban.email === email || ban.ip === ip
    }
    return false
  })

  return activeBans.length > 0 ? activeBans[0] : null
}

const banUser = (email, ip, duration, reason, adminEmail) => {
  if (!ADMIN_EMAILS.includes(adminEmail)) {
    return { success: false, error: "Unauthorized. Only admins can ban users." }
  }

  const bansData = readBans()
  const now = new Date()
  let expiresAt = null
  let permanent = false

  // Calculate expiration date based on duration
  switch (duration) {
    case "week":
      expiresAt = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000) // 7 days
      break
    case "month":
      expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000) // 30 days
      break
    case "year":
      expiresAt = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000) // 365 days
      break
    case "permanent":
      permanent = true
      break
    default:
      return { success: false, error: "Invalid ban duration" }
  }

  // Create new ban
  const newBan = {
    id: crypto.randomUUID(),
    email,
    ip,
    reason: reason || "Violation of community guidelines",
    createdAt: now.toISOString(),
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
    permanent,
    bannedBy: adminEmail,
  }

  // Remove any existing bans for this email or IP
  bansData.bans = bansData.bans.filter((ban) => ban.email !== email && ban.ip !== ip)

  // Add new ban
  bansData.bans.push(newBan)
  writeBans(bansData)

  // Log the ban
  console.log(`User banned: ${email} (${ip}) by ${adminEmail} for ${duration}. Reason: ${reason}`)

  return { success: true, ban: newBan }
}

const unbanUser = (email, adminEmail) => {
  if (!ADMIN_EMAILS.includes(adminEmail)) {
    return { success: false, error: "Unauthorized. Only admins can unban users." }
  }

  const bansData = readBans()

  // Find the ban
  const banIndex = bansData.bans.findIndex((ban) => ban.email === email)

  if (banIndex === -1) {
    return { success: false, error: "User is not banned" }
  }

  // Remove the ban
  const removedBan = bansData.bans.splice(banIndex, 1)[0]
  writeBans(bansData)

  // Log the unban
  console.log(`User unbanned: ${email} by ${adminEmail}`)

  return { success: true, unbannedUser: email }
}

// Add this function after the writeData function to handle Google authentication
const verifyGoogleToken = async (token) => {
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    })

    const payload = ticket.getPayload()
    return {
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      email_verified: payload.email_verified,
    }
  } catch (error) {
    console.error("Error verifying Google token:", error)
    return null
  }
}

// Ban check middleware
const checkBanMiddleware = (req, res, next) => {
  // Skip ban check for ban management endpoints
  if (req.path.startsWith("/api/admin/ban") || req.path.startsWith("/api/admin/unban")) {
    return next()
  }

  const email = req.body.email || req.query.email
  const ip = req.clientIp

  if (email || ip) {
    const ban = isUserBanned(email, ip)
    if (ban) {
      return res.status(403).json({
        error: "Account banned",
        reason: ban.reason,
        expiresAt: ban.expiresAt,
        permanent: ban.permanent,
      })
    }
  }

  next()
}

// Apply ban check middleware to all API routes
app.use("/api", checkBanMiddleware)

// Google OAuth login endpoint
app.get("/api/auth/google", (req, res) => {
  // Store the referrer URL to redirect back after login
  const referrer = req.headers.referer || FRONTEND_URL
  console.log("Auth request received. Referrer:", referrer)

  // Store the referrer in a cookie
  res.cookie("auth_redirect", referrer, {
    maxAge: 10 * 60 * 1000, // 10 minutes
    httpOnly: true,
    secure: true,
    sameSite: "none",
  })

  const authUrl = googleClient.generateAuthUrl({
    access_type: "offline",
    scope: ["profile", "email"],
    prompt: "consent",
    redirect_uri: REDIRECT_URI,
  })

  console.log("Redirecting to Google auth URL:", authUrl)
  res.redirect(authUrl)
})

// Google OAuth callback endpoint
app.get("/api/auth/callback/google", async (req, res) => {
  const { code } = req.query
  console.log("Received callback from Google with code:", code ? "Code received" : "No code")

  // Get the redirect URL from cookie
  const redirectUrl = req.cookies.auth_redirect || `${FRONTEND_URL}/index.html`
  console.log("Redirect URL from cookie:", redirectUrl)

  // Clear the cookie
  res.clearCookie("auth_redirect")

  if (!code) {
    console.error("No authorization code received from Google")
    return res.redirect(`${FRONTEND_URL}/signin.html?error=no_code`)
  }

  try {
    // Exchange code for tokens
    console.log("Exchanging code for tokens...")
    const { tokens } = await googleClient.getToken({
      code,
      redirect_uri: REDIRECT_URI,
    })

    const idToken = tokens.id_token
    console.log("Received tokens from Google, ID token length:", idToken ? idToken.length : 0)

    // Verify the ID token
    const userData = await verifyGoogleToken(idToken)

    if (!userData) {
      console.error("Failed to verify Google ID token")
      return res.redirect(`${FRONTEND_URL}/signin.html?error=invalid_token`)
    }

    const { email, name, picture, email_verified } = userData
    console.log("User data verified:", { email, name, email_verified })

    if (!email_verified) {
      console.error("User email not verified with Google")
      return res.redirect(`${FRONTEND_URL}/signin.html?error=email_not_verified`)
    }

    // Check if user is banned
    const ip = req.clientIp
    const ban = isUserBanned(email, ip)
    if (ban) {
      console.error("User is banned:", email)
      return res.redirect(
        `${FRONTEND_URL}/banned.html?reason=${encodeURIComponent(ban.reason)}&expires=${encodeURIComponent(ban.expiresAt || "never")}`,
      )
    }

    // Check if user exists in our database
    const data = readData()
    let user = data.users.find((u) => u.email === email)
    let needUsername = false

    if (user) {
      // Update existing user
      console.log("Updating existing user:", email)
      user.name = name
      user.avatar = picture
      user.lastLogin = new Date().toISOString()
      user.lastIp = ip // Track IP for ban purposes
    } else {
      // Create new user
      console.log("Creating new user:", email)
      user = {
        id: crypto.randomUUID(),
        email,
        name,
        avatar: picture,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
        subscription: "free", // Default subscription
        debatesJoined: 0,
        debatesCreated: 0,
        debatesJoinedToday: 0,
        lastDebateJoinDate: null,
        lastIp: ip, // Track IP for ban purposes
        ipHistory: [{ ip, timestamp: new Date().toISOString() }],
      }
      data.users.push(user)
      needUsername = true
    }

    writeData(data)

    // Generate a JWT token for the user
    const jwtToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    })
    console.log("Generated JWT token for user:", email)

    // Redirect to the frontend with user data
    if (needUsername) {
      console.log("User needs username, redirecting to username form")
      const redirectToSignin = `${FRONTEND_URL}/signin.html?token=${encodeURIComponent(jwtToken)}&email=${encodeURIComponent(email)}&name=${encodeURIComponent(name)}&avatar=${encodeURIComponent(picture)}&needUsername=true&redirect=${encodeURIComponent(redirectUrl)}`
      console.log("Redirecting to:", redirectToSignin)
      res.redirect(redirectToSignin)
    } else {
      // Redirect back to the original page
      console.log("User has username, redirecting to original page:", redirectUrl)
      const redirectWithParams = redirectUrl.includes("?")
        ? `${redirectUrl}&token=${encodeURIComponent(jwtToken)}&email=${encodeURIComponent(email)}`
        : `${redirectUrl}?token=${encodeURIComponent(jwtToken)}&email=${encodeURIComponent(email)}`

      console.log("Redirecting to:", redirectWithParams)
      res.redirect(redirectWithParams)
    }
  } catch (error) {
    console.error("Google callback error:", error)
    res.redirect(`${FRONTEND_URL}/signin.html?error=auth_error&message=${encodeURIComponent(error.message)}`)
  }
})

// Authentication endpoints
app.post("/api/auth/google", async (req, res) => {
  try {
    const { token } = req.body
    const ip = req.clientIp
    console.log("Received token verification request")

    if (!token) {
      console.error("No token provided")
      return res.status(400).json({ error: "Token is required" })
    }

    const userData = await verifyGoogleToken(token)

    if (!userData) {
      console.error("Failed to verify token")
      return res.status(401).json({ error: "Invalid token" })
    }

    const { email, name, picture, email_verified } = userData
    console.log("Token verified for user:", email)

    if (!email_verified) {
      console.error("Email not verified:", email)
      return res.status(401).json({ error: "Email not verified" })
    }

    // Check if user is banned
    const ban = isUserBanned(email, ip)
    if (ban) {
      console.error("User is banned:", email)
      return res.status(403).json({
        error: "Account banned",
        reason: ban.reason,
        expiresAt: ban.expiresAt,
        permanent: ban.permanent,
      })
    }

    // Check if user exists in our database
    const data = readData()
    let user = data.users.find((u) => u.email === email)

    if (user) {
      // Update existing user
      console.log("Updating existing user:", email)
      user.name = name
      user.avatar = picture
      user.lastLogin = new Date().toISOString()
      user.lastIp = ip

      // Add IP to history if it's different
      if (!user.ipHistory) {
        user.ipHistory = []
      }

      if (!user.ipHistory.some((entry) => entry.ip === ip)) {
        user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
      }
    } else {
      // Create new user
      console.log("Creating new user:", email)
      user = {
        id: crypto.randomUUID(),
        email,
        name,
        avatar: picture,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
        subscription: "free", // Default subscription
        debatesJoined: 0,
        debatesCreated: 0,
        debatesJoinedToday: 0,
        lastDebateJoinDate: null,
        lastIp: ip,
        ipHistory: [{ ip, timestamp: new Date().toISOString() }],
      }
      data.users.push(user)
    }

    writeData(data)

    // Generate a JWT token for the user
    const jwtToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    })
    console.log("Generated JWT token for user:", email)

    // Return user data and token
    res.json({
      token: jwtToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        avatar: user.avatar,
        subscription: user.subscription,
        subscription_expiry: user.subscription_expiry,
        isAdmin: ADMIN_EMAILS.includes(email),
      },
    })
  } catch (error) {
    console.error("Google authentication error:", error)
    res.status(500).json({ error: "Authentication failed", details: error.message })
  }
})

app.post("/api/auth/verify", (req, res) => {
  const { email } = req.body
  const ip = req.clientIp
  console.log("Verifying user:", email)

  if (!email) {
    return res.json({ valid: false })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    console.error("User is banned:", email)
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (user) {
    console.log("User verified:", email)
    // Update IP if needed
    if (user.lastIp !== ip) {
      user.lastIp = ip
      if (!user.ipHistory) {
        user.ipHistory = []
      }
      user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
      writeData(data)
    }

    res.json({
      valid: true,
      username: user.username,
      subscription: user.subscription,
      avatar: user.avatar,
      name: user.name,
      isAdmin: ADMIN_EMAILS.includes(email),
    })
  } else {
    console.log("User not found:", email)
    res.json({ valid: false })
  }
})

app.post("/api/auth/logout", (req, res) => {
  // In a real application, you might invalidate a session here
  console.log("User logged out")
  res.json({ success: true })
})

// Admin ban management endpoints
app.post("/api/admin/ban", (req, res) => {
  const { adminEmail, targetEmail, duration, reason } = req.body
  const targetIp = req.body.targetIp || null

  if (!adminEmail || !targetEmail || !duration) {
    return res.status(400).json({ error: "Admin email, target email, and duration are required" })
  }

  if (!ADMIN_EMAILS.includes(adminEmail)) {
    return res.status(403).json({ error: "Unauthorized. Only admins can ban users." })
  }

  // If no IP provided, try to find the user's last IP
  let ip = targetIp
  if (!ip) {
    const data = readData()
    const user = data.users.find((u) => u.email === targetEmail)
    if (user && user.lastIp) {
      ip = user.lastIp
    }
  }

  const result = banUser(targetEmail, ip, duration, reason, adminEmail)

  if (result.success) {
    res.json({ success: true, ban: result.ban })
  } else {
    res.status(400).json({ error: result.error })
  }
})

app.post("/api/admin/unban", (req, res) => {
  const { adminEmail, targetEmail } = req.body

  if (!adminEmail || !targetEmail) {
    return res.status(400).json({ error: "Admin email and target email are required" })
  }

  if (!ADMIN_EMAILS.includes(adminEmail)) {
    return res.status(403).json({ error: "Unauthorized. Only admins can unban users." })
  }

  const result = unbanUser(targetEmail, adminEmail)

  if (result.success) {
    res.json({ success: true, unbannedUser: result.unbannedUser })
  } else {
    res.status(400).json({ error: result.error })
  }
})

app.get("/api/admin/bans", (req, res) => {
  const { adminEmail } = req.query

  if (!adminEmail) {
    return res.status(400).json({ error: "Admin email is required" })
  }

  if (!ADMIN_EMAILS.includes(adminEmail)) {
    return res.status(403).json({ error: "Unauthorized. Only admins can view bans." })
  }

  const bansData = readBans()

  // Filter out expired bans
  const now = new Date()
  const activeBans = bansData.bans.filter((ban) => {
    return ban.permanent || (ban.expiresAt && new Date(ban.expiresAt) > now)
  })

  res.json({ bans: activeBans })
})

// User management endpoints
app.post("/api/user/update", (req, res) => {
  const { email, username } = req.body
  const ip = req.clientIp
  console.log("Updating user:", email, "with username:", username)

  if (!email || !username) {
    return res.status(400).json({ error: "Email and username are required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    console.error("User is banned:", email)
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (user) {
    user.username = username
    user.updatedAt = new Date().toISOString()

    // Update IP if needed
    if (user.lastIp !== ip) {
      user.lastIp = ip
      if (!user.ipHistory) {
        user.ipHistory = []
      }
      user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
    }

    writeData(data)
    console.log("User updated successfully:", email)

    res.json({
      success: true,
      username: user.username,
      subscription: user.subscription,
      isAdmin: ADMIN_EMAILS.includes(email),
    })
  } else {
    console.error("User not found:", email)
    res.status(404).json({ error: "User not found" })
  }
})

// Debate management endpoints
app.get("/api/debates", (req, res) => {
  const { status } = req.query
  const debatesData = readDebates()

  let filteredDebates = debatesData.debates

  if (status) {
    filteredDebates = filteredDebates.filter((debate) => debate.status === status)
  }

  res.json({ debates: filteredDebates })
})

app.get("/api/debates/:id", (req, res) => {
  const { id } = req.params
  const debatesData = readDebates()

  const debate = debatesData.debates.find((d) => d.id === id)

  if (!debate) {
    return res.status(404).json({ error: "Debate not found" })
  }

  res.json({ debate })
})

// Check if user can join more debates today
const canJoinMoreDebates = (user) => {
  // Reset daily count if it's a new day
  const today = new Date().toISOString().split("T")[0]
  const lastJoinDate = user.lastDebateJoinDate ? user.lastDebateJoinDate.split("T")[0] : null

  if (lastJoinDate !== today) {
    user.debatesJoinedToday = 0
  }

  // Check subscription limits
  let dailyLimit = 8 // Default for free users

  if (user.subscription === "pro") {
    dailyLimit = 20
  } else if (user.subscription === "elite") {
    dailyLimit = 50
  } else if (user.subscription === "institutional") {
    dailyLimit = 100
  }

  return user.debatesJoinedToday < dailyLimit
}

// Join a debate
app.post("/api/debates/:id/join", (req, res) => {
  const { id } = req.params
  const { email } = req.body
  const ip = req.clientIp

  if (!email) {
    return res.status(400).json({ error: "Email is required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update IP if needed
  if (user.lastIp !== ip) {
    user.lastIp = ip
    if (!user.ipHistory) {
      user.ipHistory = []
    }
    user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
  }

  // Check if user can join more debates today
  if (!canJoinMoreDebates(user)) {
    return res.status(403).json({
      error: "Daily debate limit reached",
      limit:
        user.subscription === "free" ? 8 : user.subscription === "pro" ? 20 : user.subscription === "elite" ? 50 : 100,
    })
  }

  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === id)

  if (!debate) {
    return res.status(404).json({ error: "Debate not found" })
  }

  if (debate.status !== "active") {
    return res.status(400).json({ error: "This debate is not currently active" })
  }

  // Check if user is already a participant
  if (debate.participants.some((p) => p.email === email)) {
    return res.status(400).json({ error: "You are already a participant in this debate" })
  }

  // Add user to participants
  debate.participants.push({
    id: user.id,
    email: user.email,
    name: user.name,
    username: user.username,
    avatar: user.avatar,
    joinedAt: new Date().toISOString(),
  })

  // Update user's debate stats
  user.debatesJoined += 1
  user.debatesJoinedToday = (user.debatesJoinedToday || 0) + 1
  user.lastDebateJoinDate = new Date().toISOString()

  // Save changes
  writeDebates(debatesData)
  writeData(data)

  // Trigger Pusher event for real-time updates
  pusher.trigger(`debate-${id}`, "user-joined", {
    user: {
      id: user.id,
      name: user.name,
      username: user.username,
      avatar: user.avatar,
    },
  })

  res.json({
    success: true,
    debate,
    debatesJoinedToday: user.debatesJoinedToday,
    dailyLimit:
      user.subscription === "free" ? 8 : user.subscription === "pro" ? 20 : user.subscription === "elite" ? 50 : 100,
  })
})

// Create a new debate
app.post("/api/debates", (req, res) => {
  const { title, description, council, email } = req.body
  const ip = req.clientIp

  if (!title || !description || !council || !email) {
    return res.status(400).json({ error: "Title, description, council, and email are required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update IP if needed
  if (user.lastIp !== ip) {
    user.lastIp = ip
    if (!user.ipHistory) {
      user.ipHistory = []
    }
    user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
  }

  // Create new debate
  const debateId = crypto.randomUUID()
  const newDebate = {
    id: debateId,
    title,
    description,
    council,
    status: "active",
    participants: [
      {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        avatar: user.avatar,
        joinedAt: new Date().toISOString(),
        isCreator: true,
      },
    ],
    createdBy: user.id,
    createdAt: new Date().toISOString(),
    startTime: new Date().toISOString(),
    endTime: null,
  }

  // Update debates file
  const debatesData = readDebates()
  debatesData.debates.push(newDebate)
  writeDebates(debatesData)

  // Update user stats
  user.debatesCreated = (user.debatesCreated || 0) + 1
  user.debatesJoined += 1
  user.debatesJoinedToday = (user.debatesJoinedToday || 0) + 1
  user.lastDebateJoinDate = new Date().toISOString()
  writeData(data)

  // Trigger Pusher event for real-time updates
  pusher.trigger("debates", "debate-created", {
    debate: newDebate,
  })

  res.json({ success: true, debate: newDebate })
})

// Chat message endpoints
app.post("/api/debates/:id/messages", (req, res) => {
  const { id } = req.params
  const { email, content } = req.body
  const ip = req.clientIp

  if (!email || !content) {
    return res.status(400).json({ error: "Email and content are required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update IP if needed
  if (user.lastIp !== ip) {
    user.lastIp = ip
    if (!user.ipHistory) {
      user.ipHistory = []
    }
    user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
    writeData(data)
  }

  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === id)

  if (!debate) {
    return res.status(404).json({ error: "Debate not found" })
  }

  // Check if user is a participant
  if (!debate.participants.some((p) => p.email === email)) {
    return res.status(403).json({ error: "You must join the debate to send messages" })
  }

  // Create new message
  const messageId = crypto.randomUUID()
  const newMessage = {
    id: messageId,
    debateId: id,
    userId: user.id,
    email: user.email,
    name: user.name,
    username: user.username,
    avatar: user.avatar,
    content,
    timestamp: new Date().toISOString(),
  }

  // Add message to messages file
  const messagesData = readMessages()
  messagesData.messages.push(newMessage)
  writeMessages(messagesData)

  // Trigger Pusher event for real-time updates
  pusher.trigger(`debate-${id}`, "new-message", newMessage)

  res.json({ success: true, message: newMessage })
})

app.get("/api/debates/:id/messages", (req, res) => {
  const { id } = req.params
  const messagesData = readMessages()

  const debateMessages = messagesData.messages.filter((m) => m.debateId === id)

  // Sort messages by timestamp
  debateMessages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))

  res.json({ messages: debateMessages })
})

// AI message generation endpoint
app.post("/api/debates/:id/ai-message", (req, res) => {
  const { id } = req.params
  const { prompt, email } = req.body
  const ip = req.clientIp

  if (!prompt || !email) {
    return res.status(400).json({ error: "Prompt and email are required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update IP if needed
  if (user.lastIp !== ip) {
    user.lastIp = ip
    if (!user.ipHistory) {
      user.ipHistory = []
    }
    user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
    writeData(data)
  }

  // Check if user has access to AI features
  if (user.subscription === "free") {
    return res
      .status(403)
      .json({ error: "AI features are only available to Pro, Elite, and Institutional subscribers" })
  }

  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === id)

  if (!debate) {
    return res.status(404).json({ error: "Debate not found" })
  }

  // Generate AI response (mock implementation)
  const aiResponses = [
    "I believe we should consider a multilateral approach to this issue, focusing on cooperation between developed and developing nations.",
    "The evidence suggests that economic incentives would be more effective than regulatory measures in this context.",
    "We must prioritize sustainable development while ensuring equitable access to resources for all nations.",
    "Historical precedents indicate that a phased implementation would yield better compliance rates.",
    "My delegation proposes a three-step plan: assessment, capacity building, and coordinated implementation.",
    "The scientific consensus clearly supports immediate action on this matter.",
    "We should establish a working group to develop comprehensive guidelines that address the concerns of all stakeholders.",
    "This issue requires balancing sovereignty concerns with our collective responsibility to the international community.",
  ]

  const aiResponse = aiResponses[Math.floor(Math.random() * aiResponses.length)]

  // Create AI message
  const messageId = crypto.randomUUID()
  const aiMessage = {
    id: messageId,
    debateId: id,
    userId: "ai-assistant",
    email: "ai@diplomaq.lol",
    name: "AI Diplomat",
    username: "ai_diplomat",
    avatar: "/images/ai-avatar.png",
    content: aiResponse,
    isAI: true,
    timestamp: new Date().toISOString(),
  }

  // Add message to messages file
  const messagesData = readMessages()
  messagesData.messages.push(aiMessage)
  writeMessages(messagesData)

  // Trigger Pusher event for real-time updates
  pusher.trigger(`debate-${id}`, "new-message", aiMessage)

  res.json({ success: true, message: aiMessage })
})

// Matchmaking endpoints
app.post("/api/matchmaking/join", (req, res) => {
  const { email, council, topic } = req.body
  const ip = req.clientIp

  if (!email || !council) {
    return res.status(400).json({ error: "Email and council are required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update IP if needed
  if (user.lastIp !== ip) {
    user.lastIp = ip
    if (!user.ipHistory) {
      user.ipHistory = []
    }
    user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
  }

  // Check if user can join more debates today
  if (!canJoinMoreDebates(user)) {
    return res.status(403).json({
      error: "Daily debate limit reached",
      limit:
        user.subscription === "free" ? 8 : user.subscription === "pro" ? 20 : user.subscription === "elite" ? 50 : 100,
    })
  }

  // Add user to matchmaking queue
  const matchmakingData = readMatchmaking()

  // Check if user is already in queue
  const existingQueueEntry = matchmakingData.queue.find((entry) => entry.userId === user.id)
  if (existingQueueEntry) {
    return res.status(400).json({ error: "You are already in the matchmaking queue" })
  }

  // Add to queue
  const queueEntry = {
    userId: user.id,
    email: user.email,
    name: user.name,
    username: user.username,
    avatar: user.avatar,
    council,
    topic: topic || null,
    joinedAt: new Date().toISOString(),
  }

  matchmakingData.queue.push(queueEntry)
  writeMatchmaking(matchmakingData)

  // Try to find a match
  const match = findMatch(queueEntry, matchmakingData.queue)

  if (match) {
    // Create a new debate for the matched users
    const debateId = crypto.randomUUID()
    const newDebate = {
      id: debateId,
      title: match.topic || `${match.council} Debate`,
      description: `Matched debate on ${match.council}`,
      council: match.council,
      status: "active",
      participants: [
        {
          id: user.id,
          email: user.email,
          name: user.name,
          username: user.username,
          avatar: user.avatar,
          joinedAt: new Date().toISOString(),
        },
        {
          id: match.userId,
          email: match.email,
          name: match.name,
          username: match.username,
          avatar: match.avatar,
          joinedAt: new Date().toISOString(),
        },
      ],
      isMatchmade: true,
      createdAt: new Date().toISOString(),
      startTime: new Date().toISOString(),
      endTime: null,
    }

    // Update debates file
    const debatesData = readDebates()
    debatesData.debates.push(newDebate)
    writeDebates(debatesData)

    // Update user stats for both users
    user.debatesJoined += 1
    user.debatesJoinedToday = (user.debatesJoinedToday || 0) + 1
    user.lastDebateJoinDate = new Date().toISOString()

    const matchedUser = data.users.find((u) => u.id === match.userId)
    if (matchedUser) {
      matchedUser.debatesJoined += 1
      matchedUser.debatesJoinedToday = (matchedUser.debatesJoinedToday || 0) + 1
      matchedUser.lastDebateJoinDate = new Date().toISOString()
    }

    writeData(data)

    // Remove both users from queue
    matchmakingData.queue = matchmakingData.queue.filter(
      (entry) => entry.userId !== user.id && entry.userId !== match.userId,
    )

    // Add to matches
    matchmakingData.matches.push({
      debateId,
      users: [user.id, match.userId],
      council: match.council,
      topic: match.topic,
      matchedAt: new Date().toISOString(),
    })

    writeMatchmaking(matchmakingData)

    // Trigger Pusher events
    pusher.trigger(`user-${user.id}`, "match-found", { debate: newDebate })
    pusher.trigger(`user-${match.userId}`, "match-found", { debate: newDebate })
    pusher.trigger("debates", "debate-created", { debate: newDebate })

    res.json({
      success: true,
      matched: true,
      debate: newDebate,
    })
  } else {
    // No match found, user is in queue
    res.json({
      success: true,
      matched: false,
      message: "You've been added to the matchmaking queue. We'll notify you when a match is found.",
    })
  }
})

app.post("/api/matchmaking/leave", (req, res) => {
  const { email } = req.body

  if (!email) {
    return res.status(400).json({ error: "Email is required" })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Remove user from matchmaking queue
  const matchmakingData = readMatchmaking()
  matchmakingData.queue = matchmakingData.queue.filter((entry) => entry.userId !== user.id)
  writeMatchmaking(matchmakingData)

  res.json({
    success: true,
    message: "You've been removed from the matchmaking queue.",
  })
})

app.get("/api/matchmaking/status", (req, res) => {
  const { email } = req.query

  if (!email) {
    return res.status(400).json({ error: "Email is required" })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Check if user is in queue
  const matchmakingData = readMatchmaking()
  const queueEntry = matchmakingData.queue.find((entry) => entry.userId === user.id)

  if (queueEntry) {
    res.json({
      inQueue: true,
      queueEntry,
      queuePosition: matchmakingData.queue.findIndex((entry) => entry.userId === user.id) + 1,
      queueSize: matchmakingData.queue.length,
    })
  } else {
    res.json({
      inQueue: false,
    })
  }
})

// Helper function to find a match
function findMatch(user, queue) {
  // Filter out the current user
  const potentialMatches = queue.filter((entry) => entry.userId !== user.userId && entry.council === user.council)

  if (potentialMatches.length === 0) {
    return null
  }

  // If user specified a topic, try to match with someone who wants the same topic
  if (user.topic) {
    const topicMatch = potentialMatches.find((entry) => entry.topic === user.topic)
    if (topicMatch) {
      return topicMatch
    }
  }

  // Otherwise, match with the user who has been waiting the longest
  potentialMatches.sort((a, b) => new Date(a.joinedAt) - new Date(b.joinedAt))
  return potentialMatches[0]
}

// Add a user profile endpoint
app.get("/api/user/profile", (req, res) => {
  const { email } = req.query
  const ip = req.clientIp

  if (!email) {
    return res.status(400).json({ error: "Email is required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update IP if needed
  if (user.lastIp !== ip) {
    user.lastIp = ip
    if (!user.ipHistory) {
      user.ipHistory = []
    }
    user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
    writeData(data)
  }

  // Check if subscription is expired
  let isExpired = false
  if (user.subscription !== "free" && user.subscription_expiry) {
    isExpired = new Date(user.subscription_expiry) < new Date()

    // Auto-downgrade expired subscriptions
    if (isExpired && user.subscription !== "free") {
      user.subscription = "free"
      user.subscription_expired_at = new Date().toISOString()
      writeData(data)
    }
  }

  // Return user profile data
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    username: user.username,
    avatar: user.avatar,
    subscription: user.subscription,
    subscription_expiry: user.subscription_expiry,
    isExpired,
    lastLogin: user.lastLogin,
    createdAt: user.createdAt,
    debatesJoined: user.debatesJoined || 0,
    debatesCreated: user.debatesCreated || 0,
    debatesJoinedToday: user.debatesJoinedToday || 0,
    isAdmin: ADMIN_EMAILS.includes(email),
  })
})

// Helper function to calculate expiry date
function calculateExpiryDate(startDate, days) {
  const expiryDate = new Date(startDate)
  expiryDate.setDate(expiryDate.getDate() + days)
  return expiryDate.toISOString()
}

// Helper function to log transactions
function logTransaction(transactionData) {
  const logFile = path.join(__dirname, "kofi_transactions.json")
  let transactions = []

  // Read existing transactions if file exists
  if (fs.existsSync(logFile)) {
    try {
      transactions = fs.readJsonSync(logFile)
    } catch (error) {
      console.error("Error reading transaction log:", error)
    }
  }

  // Add new transaction with timestamp
  transactions.push({
    ...transactionData,
    logged_at: new Date().toISOString(),
  })

  // Write updated transactions
  try {
    fs.writeJsonSync(logFile, transactions)
  } catch (error) {
    console.error("Error writing transaction log:", error)
  }
}

// Subscription management endpoints
app.get("/api/subscriptions/status", (req, res) => {
  const { email } = req.query
  const ip = req.clientIp

  if (!email) {
    return res.status(400).json({ error: "Email is required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update IP if needed
  if (user.lastIp !== ip) {
    user.lastIp = ip
    if (!user.ipHistory) {
      user.ipHistory = []
    }
    user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
    writeData(data)
  }

  // Check if subscription is expired
  let isExpired = false
  if (user.subscription !== "free" && user.subscription_expiry) {
    isExpired = new Date(user.subscription_expiry) < new Date()
  }

  res.json({
    subscription: user.subscription,
    expiry: user.subscription_expiry || null,
    isExpired,
    lastUpdated: user.subscription_updated || null,
    isAdmin: ADMIN_EMAILS.includes(email),
  })
})

// Function to verify if a user has access to a specific feature
app.get("/api/access/verify", (req, res) => {
  const { email, feature } = req.query
  const ip = req.clientIp

  if (!email || !feature) {
    return res.status(400).json({ error: "Email and feature are required" })
  }

  // Check if user is banned
  const ban = isUserBanned(email, ip)
  if (ban) {
    return res.status(403).json({
      error: "Account banned",
      reason: ban.reason,
      expiresAt: ban.expiresAt,
      permanent: ban.permanent,
    })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update IP if needed
  if (user.lastIp !== ip) {
    user.lastIp = ip
    if (!user.ipHistory) {
      user.ipHistory = []
    }
    user.ipHistory.push({ ip, timestamp: new Date().toISOString() })
    writeData(data)
  }

  // Check if subscription is expired
  let isExpired = false
  if (user.subscription !== "free" && user.subscription_expiry) {
    isExpired = new Date(user.subscription_expiry) < new Date()
  }

  // If subscription is expired, downgrade to free
  if (isExpired && user.subscription !== "free") {
    user.subscription = "free"
    user.subscription_expired_at = new Date().toISOString()
    writeData(data)
  }

  // Define feature access based on subscription level
  const featureAccess = {
    "debate-ai": ["pro", "elite", "institutional"],
    "unlimited-debates": ["pro", "elite", "institutional"],
    "advanced-analytics": ["elite", "institutional"],
    "custom-topics": ["elite", "institutional"],
    "team-management": ["institutional"],
    "white-label": ["institutional"],
    "admin-ban": ["admin"], // Special admin-only feature
  }

  // Check if user's subscription grants access to the requested feature
  let hasAccess = false

  if (feature === "admin-ban") {
    hasAccess = ADMIN_EMAILS.includes(email)
  } else {
    hasAccess = featureAccess[feature] ? featureAccess[feature].includes(user.subscription) : false
  }

  res.json({
    hasAccess,
    subscription: user.subscription,
    isExpired,
    feature,
    isAdmin: ADMIN_EMAILS.includes(email),
  })
})

// Enhanced Ko-fi webhook endpoint
app.post("/api/kofi/webhook", (req, res) => {
  try {
    console.log("Received Ko-fi webhook:", req.body)

    // Extract data from the request
    const data = req.body.data || req.body

    // Verify Ko-fi verification token
    const expectedToken = process.env.KOFI_VERIFICATION_TOKEN || "adbb7035-7f57-49ca-b3ee-5844ecb07a53"
    if (expectedToken && data.verification_token !== expectedToken) {
      console.error("Invalid verification token received:", data.verification_token)
      return res.status(401).json({ error: "Invalid verification token" })
    }

    // Extract Ko-fi data
    const {
      message_id,
      timestamp,
      type,
      is_public,
      from_name,
      message,
      amount,
      url,
      email,
      currency,
      is_subscription_payment,
      is_first_subscription_payment,
      kofi_transaction_id,
      shop_items = [],
      tier_name,
    } = data

    // Extract shipping information if available
    const shippingInfo = data.shipping_info || {}
    const { name, street_address, city, state_or_province, postal_code, country, phone_number } = shippingInfo

    // Send email with customer details
    if (email) {
      const customerDetails = {
        email,
        name: name || from_name,
        street: street_address || "Not provided",
        town: city || "Not provided",
        postcode: postal_code || "Not provided",
        phone: phone_number || "Not provided",
        amount: amount || "0.05",
        currency: currency,
        timestamp: new Date().toISOString(),
      }

      console.log("Sending customer details email:", customerDetails)
      // In a real implementation, you would send an email here
      // sendCustomerDetailsEmail(customerDetails);
    }

    console.log("Ko-fi webhook details:", {
      type,
      from_name,
      email,
      amount,
      is_subscription_payment,
      tier_name,
      kofi_transaction_id,
      timestamp,
    })

    // Handle different types of Ko-fi transactions
    switch (type) {
      case "Subscription":
        // Process subscription payment
        if (email) {
          const data = readData()
          const user = data.users.find((u) => u.email === email)

          if (user) {
            // Map tier_name directly to subscription level
            let subscriptionTier = "free"

            if (tier_name) {
              if (tier_name.toLowerCase().includes("pro")) {
                subscriptionTier = "pro"
              } else if (tier_name.toLowerCase().includes("elite")) {
                subscriptionTier = "elite"
              } else if (tier_name.toLowerCase().includes("institutional")) {
                subscriptionTier = "institutional"
              }
            }

            // Update user subscription
            user.subscription = subscriptionTier
            user.subscription_updated = new Date().toISOString()
            user.kofi_transaction_id = kofi_transaction_id
            user.subscription_expiry = calculateExpiryDate(new Date(), 30) // 30 days subscription
            user.payment_history = user.payment_history || []

            user.payment_history.push({
              type: "subscription",
              tier: subscriptionTier,
              amount,
              currency,
              transaction_id: kofi_transaction_id,
              timestamp: new Date().toISOString(),
            })

            writeData(data)

            console.log(`Updated subscription for ${email} to ${subscriptionTier}`)

            // Log transaction to a separate file for auditing
            logTransaction({
              email,
              type,
              tier_name,
              amount,
              currency,
              kofi_transaction_id,
              timestamp,
              is_first_subscription_payment,
            })

            // Send welcome email for new subscribers
            if (is_first_subscription_payment) {
              console.log(`Sending welcome email to new ${subscriptionTier} subscriber: ${email}`)
              // In a real implementation, you would send an email here
            }
          } else {
            console.log(`User with email ${email} not found, creating new user record`)

            // Create a new user if they don't exist yet
            const newUser = {
              id: crypto.randomUUID(),
              email,
              name: from_name || email.split("@")[0],
              createdAt: new Date().toISOString(),
              lastLogin: new Date().toISOString(),
              subscription: tier_name.toLowerCase().includes("pro")
                ? "pro"
                : tier_name.toLowerCase().includes("elite")
                  ? "elite"
                  : tier_name.toLowerCase().includes("institutional")
                    ? "institutional"
                    : "free",
              subscription_updated: new Date().toISOString(),
              kofi_transaction_id: kofi_transaction_id,
              subscription_expiry: calculateExpiryDate(new Date(), 30),
              payment_history: [
                {
                  type: "subscription",
                  tier: tier_name.toLowerCase().includes("pro")
                    ? "pro"
                    : tier_name.toLowerCase().includes("elite")
                      ? "elite"
                      : tier_name.toLowerCase().includes("institutional")
                        ? "institutional"
                        : "free",
                  amount,
                  currency,
                  transaction_id: kofi_transaction_id,
                  timestamp: new Date().toISOString(),
                },
              ],
            }

            data.users.push(newUser)
            writeData(data)

            console.log(`Created new user with email ${email} and subscription ${newUser.subscription}`)

            // Log transaction
            logTransaction({
              email,
              type,
              tier_name,
              amount,
              currency,
              kofi_transaction_id,
              timestamp,
              is_first_subscription_payment,
              new_user: true,
            })

            // Send welcome email
            console.log(`Sending welcome email to new user: ${email}`)
            // In a real implementation, you would send an email here
          }
        } else {
          console.error("No email provided in Ko-fi webhook data")
        }
        break

      case "Donation":
        // Handle one-time donations
        if (email) {
          const data = readData()
          const user = data.users.find((u) => u.email === email)

          if (user) {
            // Record the donation
            user.last_donation = {
              amount,
              currency,
              timestamp: new Date().toISOString(),
              kofi_transaction_id,
            }

            // If donation amount is sufficient, upgrade subscription
            const amountNum = Number.parseFloat(amount)
            let subscriptionTier = user.subscription

            if (amountNum >= 89) {
              subscriptionTier = "institutional"
            } else if (amountNum >= 11.99) {
              subscriptionTier = "elite"
            } else if (amountNum >= 4.99) {
              subscriptionTier = "pro"
            }

            // Only upgrade if the new tier is higher than current
            const tierRank = { free: 0, pro: 1, elite: 2, institutional: 3 }
            if (tierRank[subscriptionTier] > tierRank[user.subscription]) {
              user.subscription = subscriptionTier
              user.subscription_updated = new Date().toISOString()
              user.subscription_expiry = calculateExpiryDate(new Date(), 30)
              console.log(`Upgraded ${email} to ${subscriptionTier} based on donation amount`)
            }

            writeData(data)

            // Log transaction
            logTransaction({
              email,
              type: "Donation",
              amount,
              currency,
              kofi_transaction_id,
              timestamp,
              subscription_upgraded: tierRank[subscriptionTier] > tierRank[user.subscription],
            })
          } else {
            console.log(`User with email ${email} not found for donation, creating new user`)

            // Create a new user
            const newUser = {
              id: crypto.randomUUID(),
              email,
              name: from_name || email.split("@")[0],
              createdAt: new Date().toISOString(),
              lastLogin: new Date().toISOString(),
              subscription: "free",
              last_donation: {
                amount,
                currency,
                timestamp: new Date().toISOString(),
                kofi_transaction_id,
              },
            }

            const data = readData()
            data.users.push(newUser)
            writeData(data)

            console.log(`Created new user with email ${email}`)
          }
        }
        break

      case "Shop Order":
        // Handle shop orders
        console.log("Shop order received:", shop_items)

        if (email) {
          const data = readData()
          const user = data.users.find((u) => u.email === email)

          if (user) {
            user.shop_orders = user.shop_orders || []
            user.shop_orders.push({
              items: shop_items,
              amount,
              currency,
              transaction_id: kofi_transaction_id,
              timestamp: new Date().toISOString(),
            })

            writeData(data)
            console.log(`Recorded shop order for ${email}`)
          } else {
            console.log(`User with email ${email} not found for shop order, creating new user`)

            // Create a new user
            const newUser = {
              id: crypto.randomUUID(),
              email,
              name: from_name || email.split("@")[0],
              createdAt: new Date().toISOString(),
              lastLogin: new Date().toISOString(),
              subscription: "free",
              shop_orders: [
                {
                  items: shop_items,
                  amount,
                  currency,
                  transaction_id: kofi_transaction_id,
                  timestamp: new Date().toISOString(),
                },
              ],
            }

            const data = readData()
            data.users.push(newUser)
            writeData(data)

            console.log(`Created new user with email ${email} for shop order`)
          }
        }
        break

      default:
        console.log(`Unhandled Ko-fi event type: ${type}`)
    }

    res.json({ success: true, message: "Webhook processed successfully" })
  } catch (error) {
    console.error("Error processing Ko-fi webhook:", error)
    res.status(500).json({ error: "Internal server error", details: error.message })
  }
})

// Serve debates.html
app.get("/debates.html", (req, res) => {
  res.sendFile(path.join(__dirname, "debates.html"))
})

// Default route handler for the main page
app.get("/", (req, res) => {
  // Check if there are authentication parameters
  const { token, email } = req.query
  if (token && email) {
    // Redirect to index.html with auth parameters
    res.redirect(`/index.html?token=${token}&email=${encodeURIComponent(email)}`)
  } else {
    res.sendFile(path.join(__dirname, "index.html"))
  }
})

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() })
})

// Start the server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
  console.log(`Visit http://localhost:${PORT} to view the application`)
  console.log(`Ko-fi webhook endpoint: http://localhost:${PORT}/api/kofi/webhook`)
})

// Handle graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM signal received: closing HTTP server")
  server.close(() => {
    console.log("HTTP server closed")
  })
})
