const express = require("express")
const bodyParser = require("body-parser")
const cors = require("cors")
const fs = require("fs-extra")
const path = require("path")
const { OAuth2Client } = require("google-auth-library")
const dotenv = require("dotenv")
const crypto = require("crypto")

dotenv.config()

// Initialize express app
const app = express()
const PORT = process.env.PORT || 3000

// Initialize Google OAuth2 client
const googleClient = new OAuth2Client("741864469861-v3jmuek30cf8pvhdgd27d100nmpt4ot7.apps.googleusercontent.com")

// Middleware
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cors())

// Serve static files from the root directory
app.use(express.static("./"))

// Data storage path
const DATA_FILE = path.join(__dirname, "data.json")

// Initialize data file if it doesn't exist
if (!fs.existsSync(DATA_FILE)) {
  fs.writeJsonSync(DATA_FILE, { users: [] })
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

// Authentication endpoints
app.post("/api/auth/google", async (req, res) => {
  try {
    const { token } = req.body
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: "741864469861-v3jmuek30cf8pvhdgd27d100nmpt4ot7.apps.googleusercontent.com",
    })

    const payload = ticket.getPayload()
    const { email, name, picture } = payload

    // Check if user exists
    const data = readData()
    let user = data.users.find((u) => u.email === email)

    if (user) {
      // Update existing user
      user.name = name
      user.avatar = picture
      user.lastLogin = new Date().toISOString()
    } else {
      // Create new user
      user = {
        id: crypto.randomUUID(),
        email,
        name,
        avatar: picture,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
        subscription: "free", // Default subscription
      }
      data.users.push(user)
    }

    writeData(data)

    // Return user data (excluding sensitive info)
    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      username: user.username,
      avatar: user.avatar,
      subscription: user.subscription,
    })
  } catch (error) {
    console.error("Google authentication error:", error)
    res.status(401).json({ error: "Authentication failed" })
  }
})

app.post("/api/auth/verify", (req, res) => {
  const { email } = req.body

  if (!email) {
    return res.json({ valid: false })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (user) {
    res.json({
      valid: true,
      username: user.username,
      subscription: user.subscription,
    })
  } else {
    res.json({ valid: false })
  }
})

app.post("/api/auth/logout", (req, res) => {
  // In a real application, you might invalidate a session here
  res.json({ success: true })
})

// User management endpoints
app.post("/api/user/update", (req, res) => {
  const { email, username } = req.body

  if (!email || !username) {
    return res.status(400).json({ error: "Email and username are required" })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (user) {
    user.username = username
    user.updatedAt = new Date().toISOString()

    writeData(data)

    res.json({
      success: true,
      username: user.username,
      subscription: user.subscription,
    })
  } else {
    res.status(404).json({ error: "User not found" })
  }
})

// Enhanced Ko-fi webhook endpoint
app.post("/api/kofi/webhook", (req, res) => {
  try {
    console.log("Received Ko-fi webhook:", req.body)

    // Extract data from the request
    const data = req.body.data || req.body

    // Verify Ko-fi verification token
    const expectedToken = process.env.KOFI_VERIFICATION_TOKEN
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
          const userData = readData()
          const user = userData.users.find((u) => u.email === email)

          if (user) {
            // Map tier_name directly to subscription level
            let subscriptionTier = "free"

            if (tier_name) {
              if (tier_name === "Pro") {
                subscriptionTier = "pro"
              } else if (tier_name === "Elite") {
                subscriptionTier = "elite"
              } else if (tier_name === "Institutional") {
                subscriptionTier = "institutional"
              }
            }

            // Update user subscription
            user.subscription = subscriptionTier
            user.subscription_updated = new Date().toISOString()
            user.kofi_transaction_id = kofi_transaction_id
            user.subscription_expiry = calculateExpiryDate(new Date(), 30) // 30 days subscription

            writeData(userData)

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
          } else {
            console.log(`User with email ${email} not found, creating new user record`)

            // Create a new user if they don't exist yet
            const newUser = {
              id: crypto.randomUUID(),
              email,
              name: from_name || email.split("@")[0],
              createdAt: new Date().toISOString(),
              lastLogin: new Date().toISOString(),
              subscription:
                tier_name === "Pro"
                  ? "pro"
                  : tier_name === "Elite"
                    ? "elite"
                    : tier_name === "Institutional"
                      ? "institutional"
                      : "free",
              subscription_updated: new Date().toISOString(),
              kofi_transaction_id: kofi_transaction_id,
              subscription_expiry: calculateExpiryDate(new Date(), 30),
            }

            const userData = readData()
            userData.users.push(newUser)
            writeData(userData)

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
          }
        } else {
          console.error("No email provided in Ko-fi webhook data")
        }
        break

      case "Donation":
        // Handle one-time donations
        if (email) {
          const userData = readData()
          const user = userData.users.find((u) => u.email === email)

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

            writeData(userData)

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
            console.log(`User with email ${email} not found for donation`)
          }
        }
        break

      case "Shop Order":
        // Handle shop orders
        console.log("Shop order received:", shop_items)
        // Process shop items if needed
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

  if (!email) {
    return res.status(400).json({ error: "Email is required" })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
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
  })
})

// Function to verify if a user has access to a specific feature
app.get("/api/access/verify", (req, res) => {
  const { email, feature } = req.query

  if (!email || !feature) {
    return res.status(400).json({ error: "Email and feature are required" })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
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
  }

  // Check if user's subscription grants access to the requested feature
  const hasAccess = featureAccess[feature] ? featureAccess[feature].includes(user.subscription) : false

  res.json({
    hasAccess,
    subscription: user.subscription,
    isExpired,
    feature,
  })
})

// Default route handler for the main page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"))
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
