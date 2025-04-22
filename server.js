const express = require("express")
const bodyParser = require("body-parser")
const cors = require("cors")
const fs = require("fs-extra")
const path = require("path")
const { OAuth2Client } = require("google-auth-library")
const crypto = require("crypto")
const jwt = require("jsonwebtoken")
const Pusher = require("pusher")
const { Pool } = require("pg")
const requestIp = require("request-ip")
const cookieParser = require("cookie-parser")

// Import custom modules
const matchmaking = require("./matchmaking.js")
const debateHandler = require("./debate-handler")

// Initialize express app
const app = express()
const PORT = process.env.PORT || 3000

// HARDCODED CREDENTIALS
// Pusher Configuration
const PUSHER_APP_ID = "1977123"
const PUSHER_KEY = "6a59bdd1f5df05fd2554"
const PUSHER_SECRET = "aa63f3daeaacc0682e13"
const PUSHER_CLUSTER = "eu"

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = "741864469861-v3jmuek30cf8pvhdgd27d100nmpt4ot7.apps.googleusercontent.com"
const GOOGLE_CLIENT_SECRET = "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"

// JWT Secret (hardcoded)
const JWT_SECRET = "e8f5c9b3a7d1f6e2c4b8a5d9f7e3c1b6a2d4f8e5c9b3a7d1f6e2c4b8a5d9f7e3c1b6a2d4f8e5c9b3a7d1f6e2c4b8"

// URLs
const REDIRECT_URI = "https://diplomaq-production.up.railway.app/api/auth/callback/google"
const FRONTEND_URL = "https://diplomaq-production.up.railway.app"

// Initialize Google OAuth2 client
const googleClient = new OAuth2Client({
  clientId: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
})

// Admin emails with ban permissions
const ADMIN_EMAILS = ["alexandroghanem@gmail.com", "alexandroghanem1@gmail.com"]

// Initialize Pusher
let pusher = null
try {
  pusher = new Pusher({
    appId: PUSHER_APP_ID,
    key: PUSHER_KEY,
    secret: PUSHER_SECRET,
    cluster: PUSHER_CLUSTER,
    useTLS: true,
  })
  console.log("Pusher initialized successfully")
} catch (error) {
  console.error("Error initializing Pusher:", error)
  console.warn("Real-time updates will be disabled.")
}

// Initialize PostgreSQL connection
let pool
try {
  const DATABASE_URL = "postgres://postgres:postgres@postgres.railway.internal:5432/railway"
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  })
  console.log("PostgreSQL connection initialized")
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
  fs.writeJsonSync(DEBATES_FILE, { debates: [] }) // No template debates
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

// Helper functions for file operations
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

// Verify Google token
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

// Matchmaking helper function
function handleMatchmaking(user, email, council, topic, ip, res) {
  // Add user to matchmaking queue
  const matchmakingData = readMatchmaking()
  const data = readData() // Make sure we have access to the latest data

  // Check if user is already in queue
  const existingQueueEntry = matchmakingData.queue.find((entry) => entry.userId === user.id || entry.email === email)
  if (existingQueueEntry) {
    return res.status(400).json({ error: "You are already in the matchmaking queue" })
  }

  // Add to queue
  const queueEntry = {
    userId: user.id,
    email: user.email,
    name: user.name || email.split("@")[0],
    username: user.username || user.name || email.split("@")[0],
    avatar: user.avatar || "/placeholder.svg",
    council,
    topic: topic || null,
    joinedAt: new Date().toISOString(),
    lastMatchAttempt: null,
    previousMatches: user.previousMatches ? user.previousMatches.map((match) => match.userId) : [],
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
      title: match.topic || topic || `${match.council} Debate`,
      description: `Matched debate on ${match.council}`,
      council: match.council,
      topic: match.topic || topic || "Matched Debate",
      status: "active",
      participants: [
        {
          id: user.id,
          email: user.email,
          name: user.name || email.split("@")[0],
          username: user.username || user.name || email.split("@")[0],
          avatar: user.avatar || "/placeholder.svg",
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
      timerStarted: true, // Start the timer immediately with both participants
      timerStartTime: new Date().toISOString(),
      endTime: null,
    }

    // Update debates file
    const debatesData = readDebates()
    debatesData.debates.push(newDebate)
    writeDebates(debatesData)

    // Update user stats for both users
    try {
      // Get fresh user data
      const userData = readData()
      const currentUser = userData.users.find((u) => u.id === user.id || u.email === user.email)

      if (!currentUser) {
        console.error(`User not found for stats update: ${user.email}`)
      } else {
        currentUser.debatesJoined = (currentUser.debatesJoined || 0) + 1
        currentUser.debatesJoinedToday = (currentUser.debatesJoinedToday || 0) + 1
        currentUser.lastDebateJoinDate = new Date().toISOString()

        // Track previous matches
        if (!currentUser.previousMatches) {
          currentUser.previousMatches = []
        }
        currentUser.previousMatches.push({
          userId: match.userId,
          timestamp: new Date().toISOString(),
        })
      }

      const matchedUser = userData.users.find((u) => u.id === match.userId || u.email === match.email)
      if (!matchedUser) {
        console.error(`Matched user not found for stats update: ${match.email}`)
      } else {
        matchedUser.debatesJoined = (matchedUser.debatesJoined || 0) + 1
        matchedUser.debatesJoinedToday = (matchedUser.debatesJoinedToday || 0) + 1
        matchedUser.lastDebateJoinDate = new Date().toISOString()

        // Track previous matches
        if (!matchedUser.previousMatches) {
          matchedUser.previousMatches = []
        }
        matchedUser.previousMatches.push({
          userId: user.id,
          timestamp: new Date().toISOString(),
        })
      }

      writeData(userData)
    } catch (error) {
      console.error("Error updating user stats:", error)
      // Continue without failing the matchmaking process
    }

    // Remove both users from queue
    matchmakingData.queue = matchmakingData.queue.filter(
      (entry) => entry.userId !== user.id && entry.userId !== match.userId,
    )

    // Add to matches
    matchmakingData.matches.push({
      debateId,
      users: [user.id, match.userId],
      council: match.council,
      topic: match.topic || topic,
      matchedAt: new Date().toISOString(),
    })

    writeMatchmaking(matchmakingData)

    // Trigger Pusher events if Pusher is initialized
    if (pusher) {
      try {
        pusher
          .trigger(`user-${user.id}`, "match-found", { debate: newDebate })
          .catch((err) => console.error("Pusher error:", err))
        pusher
          .trigger(`user-${match.userId}`, "match-found", { debate: newDebate })
          .catch((err) => console.error("Pusher error:", err))
        pusher
          .trigger("debates", "debate-created", { debate: newDebate })
          .catch((err) => console.error("Pusher error:", err))
      } catch (error) {
        console.error("Error triggering Pusher events:", error)
      }
    }

    return res.json({
      success: true,
      matched: true,
      debate: newDebate,
    })
  } else {
    // No match found, user is in queue
    return res.json({
      success: true,
      matched: false,
      message: "You've been added to the matchmaking queue. We'll notify you when a match is found.",
    })
  }
}

// Helper function to find a match
function findMatch(user, queue) {
  // Filter out the current user
  const potentialMatches = queue.filter((entry) => {
    // Don't match with self
    if (entry.userId === user.userId) return false

    // Must be same council
    if (entry.council !== user.council) return false

    // Check if users have been matched before (avoid matching with same users)
    if (user.previousMatches && user.previousMatches.some((match) => match.userId === entry.userId)) {
      return false
    }

    // If both users specified a topic, they should match on topic
    if (user.topic && entry.topic && user.topic !== entry.topic) {
      return false
    }

    return true
  })

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
    include_granted_scopes: true,
  })

  console.log("Redirecting to Google auth URL:", authUrl)
  res.redirect(authUrl)
})

// Google OAuth callback endpoint
app.get("/api/auth/callback/google", async (req, res) => {
  const { code, error } = req.query
  console.log("Received callback from Google with code:", code ? "Code received" : "No code")

  if (error) {
    console.error("Error returned from Google OAuth:", error)
    return res.redirect(`${FRONTEND_URL}/signin.html?error=${error}`)
  }

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
    res.redirect(
      `${FRONTEND_URL}/signin.html?error=auth_error&message=${encodeURIComponent(error.message || "Authentication failed")}`,
    )
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
    return res.status(500).json({ error: "Authentication failed" })
  }
})

app.post("/api/auth/verify", (req, res) => {
  const { email } = req.body
  const ip = req.clientIp

  if (!email) {
    console.error("No email provided")
    return res.status(400).json({ error: "Email is required" })
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
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    console.error("User not found:", email)
    return res.status(404).json({ error: "User not found" })
  }

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
})

// User endpoints
app.post("/api/user/update-username", (req, res) => {
  const { token, username } = req.body

  if (!token) {
    console.error("No token provided")
    return res.status(400).json({ error: "Token is required" })
  }

  if (!username) {
    console.error("No username provided")
    return res.status(400).json({ error: "Username is required" })
  }

  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, JWT_SECRET)

    // Extract user ID and email from the decoded token
    const { id, email } = decoded

    // Read user data
    const data = readData()

    // Find the user by ID and email
    const user = data.users.find((u) => u.id === id && u.email === email)

    if (!user) {
      console.error("User not found")
      return res.status(404).json({ error: "User not found" })
    }

    // Check if the username is already taken
    const usernameTaken = data.users.some((u) => u.username === username && u.id !== id)

    if (usernameTaken) {
      console.error("Username already taken")
      return res.status(400).json({ error: "Username already taken" })
    }

    // Update the username
    user.username = username

    // Write the updated data
    writeData(data)

    // Generate a new JWT token with the updated user data
    const jwtToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    })
    console.log("Generated new JWT token for user:", email)

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
    console.error("Error updating username:", error)
    return res.status(500).json({ error: "Failed to update username" })
  }
})

// Admin endpoints
app.post("/api/admin/ban", (req, res) => {
  const { email, ip, duration, reason, adminEmail } = req.body

  if (!adminEmail) {
    return res.status(400).json({ error: "Admin email is required" })
  }

  if (!email && !ip) {
    return res.status(400).json({ error: "Email or IP is required" })
  }

  if (!duration) {
    return res.status(400).json({ error: "Ban duration is required" })
  }

  const result = banUser(email, ip, duration, reason, adminEmail)

  if (result.success) {
    res.json({ success: true, ban: result.ban })
  } else {
    res.status(400).json({ success: false, error: result.error })
  }
})

app.post("/api/admin/unban", (req, res) => {
  const { email, adminEmail } = req.body

  if (!adminEmail) {
    return res.status(400).json({ error: "Admin email is required" })
  }

  if (!email) {
    return res.status(400).json({ error: "Email is required" })
  }

  const result = unbanUser(email, adminEmail)

  if (result.success) {
    res.json({ success: true, unbannedUser: result.unbannedUser })
  } else {
    res.status(400).json({ success: false, error: result.error })
  }
})

// Matchmaking endpoints
app.post("/api/matchmaking/join", (req, res) => {
  const { token, council, topic } = req.body
  const ip = req.clientIp

  if (!token) {
    return res.status(400).json({ error: "Token is required" })
  }

  if (!council) {
    return res.status(400).json({ error: "Council is required" })
  }

  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, JWT_SECRET)

    // Extract user ID and email from the decoded token
    const { id, email } = decoded

    // Read user data
    const data = readData()

    // Find the user by ID and email
    const user = data.users.find((u) => u.id === id && u.email === email)

    if (!user) {
      console.error("User not found")
      return res.status(404).json({ error: "User not found" })
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

    // Check if user can join more debates today
    if (!canJoinMoreDebates(user)) {
      return res.status(403).json({
        error: "Daily debate limit reached",
      })
    }

    handleMatchmaking(user, email, council, topic, ip, res)
  } catch (error) {
    console.error("Matchmaking join error:", error)
    return res.status(500).json({ error: "Matchmaking failed" })
  }
})

app.post("/api/matchmaking/leave", (req, res) => {
  const { token } = req.body

  if (!token) {
    return res.status(400).json({ error: "Token is required" })
  }

  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, JWT_SECRET)

    // Extract user ID and email from the decoded token
    const { id, email } = decoded

    // Read matchmaking data
    const matchmakingData = readMatchmaking()

    // Remove user from queue
    matchmakingData.queue = matchmakingData.queue.filter((entry) => entry.userId !== id && entry.email !== email)
    writeMatchmaking(matchmakingData)

    res.json({ success: true, message: "You have left the matchmaking queue" })
  } catch (error) {
    console.error("Matchmaking leave error:", error)
    return res.status(500).json({ error: "Failed to leave matchmaking" })
  }
})

// Debate endpoints
app.get("/api/debates", (req, res) => {
  try {
    const debatesData = readDebates()
    res.json(debatesData.debates)
  } catch (error) {
    console.error("Error fetching debates:", error)
    res.status(500).json({ error: "Failed to fetch debates" })
  }
})

app.get("/api/debates/:id", (req, res) => {
  try {
    const { id } = req.params
    const debatesData = readDebates()
    const debate = debatesData.debates.find((debate) => debate.id === id)

    if (debate) {
      res.json({ success: true, debate })
    } else {
      res.status(404).json({ success: false, error: "Debate not found" })
    }
  } catch (error) {
    console.error("Error fetching debate:", error)
    res.status(500).json({ success: false, error: "Failed to fetch debate" })
  }
})

// Add routes for debate messages
// Add these routes before the "Start the server" line:

// Debate messages endpoints
app.get("/api/debates/:id/messages", (req, res) => {
  try {
    const { id } = req.params
    const messagesData = readMessages()
    const messages = messagesData.messages.filter((message) => message.debateId === id)

    res.json({ success: true, messages })
  } catch (error) {
    console.error("Error fetching messages:", error)
    res.status(500).json({ success: false, error: "Failed to fetch messages" })
  }
})

app.post("/api/debates/:id/messages", (req, res) => {
  try {
    const { id } = req.params
    const { email, content } = req.body

    if (!email || !content) {
      return res.status(400).json({ success: false, error: "Email and content are required" })
    }

    // Get user
    const userData = readData()
    const user = userData.users.find((u) => u.email === email)

    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" })
    }

    // Get debate
    const debatesData = readDebates()
    const debate = debatesData.debates.find((d) => d.id === id)

    if (!debate) {
      return res.status(404).json({ success: false, error: "Debate not found" })
    }

    // Check if debate is active
    if (debate.status !== "active") {
      return res.status(400).json({ success: false, error: "This debate is not currently active" })
    }

    // Check if user is a participant
    if (!debate.participants.some((p) => p.email === email)) {
      return res.status(403).json({ success: false, error: "You are not a participant in this debate" })
    }

    // Check if there are at least 2 participants
    if (debate.participants.length < 2) {
      return res.status(400).json({ success: false, error: "You need at least 2 participants to start messaging" })
    }

    // Create message
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

    // Trigger Pusher event if available
    if (pusher) {
      try {
        pusher.trigger(`debate-${id}`, "new-message", newMessage)
      } catch (error) {
        console.error("Error triggering Pusher event:", error)
      }
    }

    res.json({ success: true, message: newMessage })
  } catch (error) {
    console.error("Error sending message:", error)
    res.status(500).json({ success: false, error: "Failed to send message" })
  }
})

// Debate timer endpoint
app.get("/api/debates/:id/timer", (req, res) => {
  try {
    const { id } = req.params
    const debatesData = readDebates()
    const debate = debatesData.debates.find((d) => d.id === id)

    if (!debate) {
      return res.status(404).json({ success: false, error: "Debate not found" })
    }

    // If timer hasn't started yet (less than 2 participants)
    if (!debate.timerStarted || !debate.timerStartTime) {
      return res.json({
        success: true,
        timerStarted: false,
        timeRemaining: 35 * 60, // 35 minutes in seconds
      })
    }

    // Calculate remaining time
    const startTime = new Date(debate.timerStartTime).getTime()
    const now = Date.now()
    const elapsedSeconds = Math.floor((now - startTime) / 1000)
    const remainingSeconds = Math.max(0, 35 * 60 - elapsedSeconds)

    return res.json({
      success: true,
      timerStarted: true,
      timeRemaining: remainingSeconds,
      startTime: debate.timerStartTime,
    })
  } catch (error) {
    console.error("Error getting timer status:", error)
    res.status(500).json({ success: false, error: "Failed to get timer status" })
  }
})

// Access verification endpoint
app.get("/api/access/verify", (req, res) => {
  const { email, feature } = req.query

  if (!email) {
    return res.status(400).json({ success: false, error: "Email is required" })
  }

  // Get user
  const userData = readData()
  const user = userData.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ success: false, error: "User not found" })
  }

  // Check if user has access to the feature
  let hasAccess = false

  if (feature === "debate-ai") {
    // AI features are available to Pro, Elite, and Institutional subscribers
    hasAccess = ["pro", "elite", "institutional"].includes(user.subscription)
  }

  res.json({ success: true, hasAccess })
})

// Save debate to profile
app.post("/api/debates/:id/save", (req, res) => {
  try {
    const { id } = req.params
    const { email } = req.body

    if (!email) {
      return res.status(400).json({ success: false, error: "Email is required" })
    }

    // Get user
    const userData = readData()
    const user = userData.users.find((u) => u.email === email)

    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" })
    }

    // Get debate
    const debatesData = readDebates()
    const debate = debatesData.debates.find((d) => d.id === id)

    if (!debate) {
      return res.status(404).json({ success: false, error: "Debate not found" })
    }

    // Check if debate is already in user's history
    if (user.debateHistory && user.debateHistory.some((d) => d.debateId === id)) {
      return res.status(400).json({ success: false, error: "Debate already saved to profile" })
    }

    // Add to user's debate history
    if (!user.debateHistory) {
      user.debateHistory = []
    }

    const userParticipant = debate.participants.find((p) => p.email === email)

    user.debateHistory.push({
      debateId: id,
      title: debate.title,
      council: debate.council,
      topic: debate.topic,
      joinedAt: userParticipant?.joinedAt || debate.startTime,
      leftAt: new Date().toISOString(),
    })

    // Update user data
    const userIndex = userData.users.findIndex((u) => u.email === email)
    if (userIndex !== -1) {
      userData.users[userIndex] = user
      writeData(userData)
    }

    res.json({ success: true })
  } catch (error) {
    console.error("Error saving debate to profile:", error)
    res.status(500).json({ success: false, error: "Failed to save debate to profile" })
  }
})

// Debate voting endpoint
app.post("/api/debates/:id/vote", (req, res) => {
  try {
    const { id } = req.params
    const { email, votedFor } = req.body

    if (!email || !votedFor) {
      return res.status(400).json({ success: false, error: "Email and votedFor are required" })
    }

    // Get debate
    const debatesData = readDebates()
    const debate = debatesData.debates.find((d) => d.id === id)

    if (!debate) {
      return res.status(404).json({ success: false, error: "Debate not found" })
    }

    // Check if debate is completed or expired
    if (debate.status !== "completed" && debate.status !== "expired") {
      return res.status(400).json({ success: false, error: "Voting is only allowed for completed or expired debates" })
    }

    // Check if user is a participant
    if (!debate.participants.some((p) => p.email === email)) {
      return res.status(403).json({ success: false, error: "You are not a participant in this debate" })
    }

    // Check if user has already voted
    if (debate.userVotes && debate.userVotes[email]) {
      return res.status(400).json({ success: false, error: "You have already voted in this debate" })
    }

    // Initialize votes if not exists
    if (!debate.votes) {
      debate.votes = {}
    }

    // Initialize userVotes if not exists
    if (!debate.userVotes) {
      debate.userVotes = {}
    }

    // Add vote
    debate.votes[votedFor] = (debate.votes[votedFor] || 0) + 1
    debate.userVotes[email] = votedFor

    // Update debates file
    writeDebates(debatesData)

    res.json({ success: true })
  } catch (error) {
    console.error("Error processing vote:", error)
    res.status(500).json({ success: false, error: "Failed to process vote" })
  }
})

// Add AI assistance endpoint
app.post("/api/debates/:id/ai-message", (req, res) => {
  try {
    const { id } = req.params
    const { email, prompt } = req.body

    if (!email || !prompt) {
      return res.status(400).json({ success: false, error: "Email and prompt are required" })
    }

    // Get user
    const userData = readData()
    const user = userData.users.find((u) => u.email === email)

    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" })
    }

    // Check if user has access to AI features
    if (!["pro", "elite", "institutional"].includes(user.subscription)) {
      return res
        .status(403)
        .json({ success: false, error: "AI assistance requires a Pro, Elite, or Institutional subscription" })
    }

    // Get debate
    const debatesData = readDebates()
    const debate = debatesData.debates.find((d) => d.id === id)

    if (!debate) {
      return res.status(404).json({ success: false, error: "Debate not found" })
    }

    // Check if user is a participant
    if (!debate.participants.some((p) => p.email === email)) {
      return res.status(403).json({ success: false, error: "You are not a participant in this debate" })
    }

    // Generate AI response based on prompt and debate context
    const aiResponse = generateAIResponse(prompt, debate.topic, debate.council)

    // Create AI message (but don't save it to the messages file)
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

    res.json({ success: true, message: aiMessage })
  } catch (error) {
    console.error("Error generating AI message:", error)
    res.status(500).json({ success: false, error: "Failed to generate AI message" })
  }
})

// Helper function to generate AI responses
function generateAIResponse(prompt, topic, council) {
  // Simple AI response generation based on prompt, topic, and council
  // In a real implementation, this would use a more sophisticated AI model

  const topicResponses = {
    "Climate Change": [
      "The scientific consensus on climate change is clear. We must take immediate action to reduce carbon emissions and transition to renewable energy sources.",
      "Developing nations require financial and technological support to adapt to climate change while pursuing sustainable development.",
      "A global carbon pricing mechanism could create the economic incentives needed to drive meaningful climate action across all sectors.",
    ],
    "Nuclear Disarmament": [
      "Nuclear disarmament must be pursued through a step-by-step approach that ensures strategic stability at each stage.",
      "The Non-Proliferation Treaty remains the cornerstone of global nuclear governance, but we must strengthen its verification mechanisms.",
      "Regional nuclear-weapon-free zones have proven effective and should be expanded to other regions facing nuclear tensions.",
    ],
    "Human Rights": [
      "Human rights are universal, indivisible, and inalienable. They apply to all persons regardless of nationality, race, religion, or any other status.",
      "Economic development and human rights protection are mutually reinforcing goals that must be pursued simultaneously.",
      "International human rights mechanisms must be strengthened to ensure accountability for violations wherever they occur.",
    ],
  }

  const councilResponses = {
    UNSC: [
      "As a Security Council matter, this issue directly impacts international peace and security.",
      "The Security Council must consider both immediate crisis response and long-term stability measures.",
      "Any resolution must balance sovereignty concerns with the Council's responsibility to maintain international peace.",
    ],
    UNGA: [
      "The General Assembly's universal membership makes it the ideal forum for building global consensus on this issue.",
      "While General Assembly resolutions are non-binding, they carry significant moral and political weight.",
      "This issue requires the broad-based approach that only the General Assembly can provide.",
    ],
    UNHRC: [
      "Human rights considerations must be central to our approach on this issue.",
      "The Human Rights Council should establish a special rapporteur to monitor and report on this situation.",
      "We must ensure that vulnerable populations are protected and their voices heard in this process.",
    ],
    ECOSOC: [
      "Economic and social factors are key drivers that must be addressed for a sustainable solution.",
      "ECOSOC's multi-stakeholder approach is essential for addressing the complex dimensions of this issue.",
      "Development considerations must be integrated into our policy response.",
    ],
  }

  // Select responses based on topic and council
  let possibleResponses = []

  // Add topic-specific responses if available
  for (const key in topicResponses) {
    if (topic && topic.toLowerCase().includes(key.toLowerCase())) {
      possibleResponses = possibleResponses.concat(topicResponses[key])
      break
    }
  }

  // Add council-specific responses if available
  if (councilResponses[council]) {
    possibleResponses = possibleResponses.concat(councilResponses[council])
  }

  // Add generic diplomatic responses if no specific ones are available
  if (possibleResponses.length === 0) {
    possibleResponses = [
      "Based on diplomatic principles and international norms, I would approach this issue with careful consideration of all stakeholders' interests.",
      "A balanced approach that considers both immediate concerns and long-term implications would be most effective here.",
      "International cooperation and multilateral engagement are essential for addressing this complex issue effectively.",
      "We must ensure that any solution respects sovereignty while promoting collective action for the common good.",
      "Evidence-based policymaking should guide our approach to this issue, drawing on best practices and lessons learned.",
    ]
  }

  // Select a random response
  const randomResponse = possibleResponses[Math.floor(Math.random() * possibleResponses.length)]

  // Add a prefix that acknowledges the prompt
  const prefixes = [
    `Regarding your question about ${prompt.substring(0, 30)}..., `,
    `In response to your inquiry on ${prompt.substring(0, 30)}..., `,
    `Considering your point about ${prompt.substring(0, 30)}..., `,
    `Addressing your concern on ${prompt.substring(0, 30)}..., `,
  ]

  const randomPrefix = prefixes[Math.floor(Math.random() * prefixes.length)]

  return randomPrefix + randomResponse
}

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
