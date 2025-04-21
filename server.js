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

// Load environment variables
dotenv.config()

// Import custom modules
const matchmaking = require("./matchmaking.js")
const debateHandler = require("./debate-handler")

// Initialize express app
const app = express()
const PORT = process.env.PORT || 3000

// Google OAuth configuration using environment variables
const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID || "741864469861-v3jmuek30cf8pvhdgd27d100nmpt4ot7.apps.googleusercontent.com"
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "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"
const JWT_SECRET = process.env.JWT_SECRET || "diplomaq-secret-key" // JWT secret
const REDIRECT_URI = process.env.REDIRECT_URI || "https://diplomaq-production.up.railway.app/api/auth/callback/google"
const FRONTEND_URL = process.env.FRONTEND_URL || "https://diplomaq-production.up.railway.app"

// Initialize Google OAuth2 client
const googleClient = new OAuth2Client({
  clientId: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
})

// Admin emails with ban permissions
const ADMIN_EMAILS = ["alexandroghanem@gmail.com", "alexandroghanem1@gmail.com"]

// Initialize Pusher using environment variables
const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID || "1722312",
  key: process.env.PUSHER_KEY || "e0e0b1c2d82c9f93b0cb",
  secret: process.env.PUSHER_SECRET || "adbb7035-7f57-49ca-b3ee-5844ecb07a53",
  cluster: process.env.PUSHER_CLUSTER || "eu",
  useTLS: true,
})

// Initialize PostgreSQL connection using environment variables
let pool
try {
  if (process.env.DATABASE_URL) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
    console.log("PostgreSQL connection initialized using DATABASE_URL")
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

    // Trigger Pusher events
    pusher.trigger(`user-${user.id}`, "match-found", { debate: newDebate })
    pusher.trigger(`user-${match.userId}`, "match-found", { debate: newDebate })
    pusher.trigger("debates", "debate-created", { debate: newDebate })

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
      id: user.id,
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

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  // Update username
  user.username = username

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
})

// User profile endpoint
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

  // Return user profile data
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    username: user.username,
    avatar: user.avatar,
    subscription: user.subscription,
    subscription_expiry: user.subscription_expiry,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin,
    debatesJoined: user.debatesJoined || 0,
    debatesCreated: user.debatesCreated || 0,
    debatesJoinedToday: user.debatesJoinedToday || 0,
    isAdmin: ADMIN_EMAILS.includes(email),
  })
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

// Create a new debate
app.post("/api/debates", (req, res) => {
  const { title, description, council, topic, email } = req.body
  const ip = req.clientIp

  if (!title || !description || !council || !email) {
    return res.status(400).json({ error: "Title, description, council, and email are required" })
  }

  // Check if council is allowed
  if (!debateHandler.ALLOWED_COUNCILS.includes(council)) {
    return res.status(400).json({ error: "Invalid council. Only UN councils are allowed." })
  }

  // Filter curse words
  const filteredTitle = filterCurseWords(title)
  const filteredDescription = filterCurseWords(description)
  const filteredTopic = filterCurseWords(topic)

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
    title: filteredTitle,
    description: filteredDescription,
    council,
    topic: filteredTopic || "General",
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
    timerStarted: false, // Timer will start when second participant joins
    timerStartTime: null,
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

  // Read fresh data to ensure we have the latest
  const data = readData()
  const debatesData = readDebates()

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

  const debate = debatesData.debates.find((d) => d.id === id)

  if (!debate) {
    return res.status(404).json({ error: "Debate not found" })
  }

  if (debate.status !== "active") {
    return res.status(400).json({ error: "This debate is not currently active" })
  }

  // Initialize participants array if it doesn't exist
  if (!debate.participants) {
    debate.participants = []
  }

  // Check if user is already a participant
  const isParticipant = debate.participants.some((p) => p.email === email)

  if (isParticipant) {
    // User is already a participant, just return success with the debate data
    return res.json({
      success: true,
      debate,
      alreadyJoined: true,
    })
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

  // Start timer if this is the second participant
  if (debate.participants.length === 2 && !debate.timerStarted) {
    debate.timerStarted = true
    debate.timerStartTime = new Date().toISOString()
  }

  // Update user's debate stats
  user.debatesJoined = (user.debatesJoined || 0) + 1
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

  // Also trigger timer started event if this is the second participant
  if (debate.participants.length === 2) {
    pusher.trigger(`debate-${id}`, "timer-started", {
      timerStarted: true,
      timerStartTime: debate.timerStartTime,
    })
  }

  res.json({
    success: true,
    debate,
    debatesJoinedToday: user.debatesJoinedToday,
    dailyLimit:
      user.subscription === "free" ? 8 : user.subscription === "pro" ? 20 : user.subscription === "elite" ? 50 : 100,
  })
})

// Leave a debate
app.post("/api/debates/:id/leave", (req, res) => {
  const { id } = req.params
  const { email, saveToProfile } = req.body
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

  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === id)

  if (!debate) {
    return res.status(404).json({ error: "Debate not found" })
  }

  // Check if user is a participant
  if (!debate.participants.some((p) => p.email === email)) {
    return res.status(403).json({ error: "You are not a participant in this debate" })
  }

  // Remove user from participants
  debate.participants = debate.participants.filter((p) => p.email !== email)

  // If no participants left, mark debate as completed
  if (debate.participants.length === 0) {
    debate.status = "completed"
    debate.endTime = new Date().toISOString()
  }

  // Update debates file
  writeDebates(debatesData)

  // Save to profile if requested
  if (saveToProfile) {
    if (!user.debateHistory) {
      user.debateHistory = []
    }

    user.debateHistory.push({
      debateId: id,
      title: debate.title,
      council: debate.council,
      topic: debate.topic,
      joinedAt: debate.participants.find((p) => p.email === email)?.joinedAt || debate.startTime,
      leftAt: new Date().toISOString(),
    })

    writeData(data)
  }

  // Trigger Pusher event for real-time updates
  pusher.trigger(`debate-${id}`, "user-left", {
    email,
  })

  res.json({ success: true })
})

// Chat message endpoints
app.post("/api/debates/:id/messages", (req, res) => {
  const { id } = req.params
  const { email, content } = req.body
  const ip = req.clientIp

  if (!email || !content) {
    return res.status(400).json({ error: "Email and content are required" })
  }

  // Filter curse words
  const filteredContent = filterCurseWords(content)

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

  // Check if there are at least 2 participants
  if (debate.participants.length < 2) {
    return res.status(403).json({ error: "You need at least 2 participants to start messaging" })
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
    content: filteredContent,
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

// Get debate timer
app.get("/api/debates/:id/timer", (req, res) => {
  const { id } = req.params

  // Get timer status
  const result = debateHandler.getDebateTimer(id)

  if (result.success) {
    res.json(result)
  } else {
    res.status(404).json({ error: result.error })
  }
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

  // If user not found, create a temporary user record
  if (!user) {
    console.log(`User with email ${email} not found for matchmaking, creating temporary record`)
    const tempUser = {
      id: crypto.randomUUID(),
      email,
      name: email.split("@")[0],
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      lastIp: ip,
      debatesJoined: 0,
      debatesCreated: 0,
      debatesJoinedToday: 0,
      ipHistory: [{ ip, timestamp: new Date().toISOString() }],
    }

    data.users.push(tempUser)
    writeData(data)

    // Continue with the newly created user
    return handleMatchmaking(tempUser, email, council, topic, ip, res)
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

  // Check if user can join more debates today
  if (!canJoinMoreDebates(user)) {
    return res.status(403).json({
      error: "Daily debate limit reached",
      limit:
        user.subscription === "free" ? 8 : user.subscription === "pro" ? 20 : user.subscription === "elite" ? 50 : 100,
    })
  }

  return handleMatchmaking(user, email, council, topic, ip, res)
})

app.post("/api/matchmaking/leave", (req, res) => {
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

  const matchmakingData = readMatchmaking()

  // Check if user is in queue
  const queueEntry = matchmakingData.queue.find((entry) => entry.email === email)

  if (!queueEntry) {
    return res.status(400).json({ error: "You are not in the matchmaking queue" })
  }

  // Remove user from queue
  matchmakingData.queue = matchmakingData.queue.filter((entry) => entry.email !== email)
  writeMatchmaking(matchmakingData)

  // Trigger Pusher event
  if (pusher) {
    pusher.trigger(`user-${queueEntry.userId}`, "queue-left", {
      timestamp: new Date().toISOString(),
    })
  }

  res.json({ success: true })
})

app.get("/api/matchmaking/status", (req, res) => {
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

  const matchmakingData = readMatchmaking()

  // Check if user is in queue
  const queueIndex = matchmakingData.queue.findIndex((entry) => entry.email === email)

  if (queueIndex === -1) {
    // Check if user has a recent match
    const data = readData()
    const user = data.users.find((u) => u.email === email)

    if (!user) {
      return res.json({ inQueue: false })
    }

    const recentMatches = matchmakingData.matches.filter(
      (match) => match.users.includes(user.id) && new Date(match.matchedAt) > new Date(Date.now() - 60 * 1000), // Matches in the last minute
    )

    if (recentMatches.length > 0) {
      const mostRecentMatch = recentMatches[recentMatches.length - 1]

      // Look up the debate
      const debatesData = readDebates()
      const debate = debatesData.debates.find((d) => d.id === mostRecentMatch.debateId)

      if (debate) {
        return res.json({
          inQueue: false,
          matched: true,
          debate: debate,
        })
      }
    }

    return res.json({ inQueue: false })
  }

  return res.json({
    inQueue: true,
    queueEntry: matchmakingData.queue[queueIndex],
    queuePosition: queueIndex + 1,
    queueSize: matchmakingData.queue.length,
  })
})

// Quick match endpoints
app.post("/api/matchmaking/quick-match", (req, res) => {
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

  // Call matchmaking function that handles creating AI debates
  return matchmaking.requestQuickMatch(email, council, topic, req.clientIp, res)
})

// Function to filter curse words in text
function filterCurseWords(text) {
  if (!text) return text

  // Simple list of curse words to filter
  const curseWords = [
    "fuck",
    "shit",
    "ass",
    "bitch",
    "cunt",
    "dick",
    "pussy",
    "cock",
    "whore",
    "slut",
    "bastard",
    "damn",
    "hell",
    "piss",
    "crap",
    "nigger",
    "faggot",
    "retard",
  ]

  let filteredText = text
  curseWords.forEach((word) => {
    const regex = new RegExp("\\b" + word + "\\b", "gi")
    filteredText = filteredText.replace(regex, "***")
  })

  return filteredText
}

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() })
})

// Start the server
const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
  console.log(`Visit http://localhost:${PORT} to view the application`)
  console.log(`Google OAuth configured with Client ID: ${GOOGLE_CLIENT_ID.substring(0, 10)}...`)

  // Initialize matchmaking with Pusher
  if (typeof matchmaking.init === "function") {
    matchmaking.init(pusher)
    console.log("Matchmaking module initialized with Pusher")
  }

  // Periodically check debate expiry
  setInterval(debateHandler.checkDebateExpiry, 60 * 1000)
})

// Handle graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM signal received: closing HTTP server")
  server.close(() => {
    console.log("HTTP server closed")
  })
})
