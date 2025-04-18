const express = require("express")
const bodyParser = require("body-parser")
const cors = require("cors")
const fs = require("fs-extra")
const path = require("path")
const { OAuth2Client } = require("google-auth-library")
const dotenv = require("dotenv")
const crypto = require("crypto")
const jwt = require("jsonwebtoken")
const axios = require("axios")
const querystring = require("querystring")

dotenv.config()

// Initialize express app
const app = express()
const PORT = process.env.PORT || 3000

// Google OAuth configuration
const GOOGLE_CLIENT_ID = "741864469861-v3jmuek30cf8pvhdgd27d100nmpt4ot7.apps.googleusercontent.com"
const GOOGLE_CLIENT_SECRET = "GOCSPX-Ow-Iy-Iy-Iy-Iy-Iy-Iy-Iy-Iy-Iy-Iy" // Replace with your actual client secret
const JWT_SECRET = "diplomaq-secret-key" // Replace with a strong secret in production
const REDIRECT_URI = "https://diplomaq-production.up.railway.app/api/auth/callback/google"
const FRONTEND_URL = "https://diplomaq-production.up.railway.app"

// Initialize Google OAuth2 client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI)

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

// Google OAuth login endpoint
app.get("/api/auth/google", (req, res) => {
  const authUrl = googleClient.generateAuthUrl({
    access_type: "offline",
    scope: ["profile", "email"],
    prompt: "consent",
  })
  res.redirect(authUrl)
})

// Google OAuth callback endpoint
app.get("/api/auth/callback/google", async (req, res) => {
  const { code } = req.query

  if (!code) {
    return res.redirect(`${FRONTEND_URL}/signin.html?error=no_code`)
  }

  try {
    // Exchange code for tokens
    const { tokens } = await googleClient.getToken(code)
    const idToken = tokens.id_token

    // Verify the ID token
    const userData = await verifyGoogleToken(idToken)

    if (!userData) {
      return res.redirect(`${FRONTEND_URL}/signin.html?error=invalid_token`)
    }

    const { email, name, picture, email_verified } = userData

    if (!email_verified) {
      return res.redirect(`${FRONTEND_URL}/signin.html?error=email_not_verified`)
    }

    // Check if user exists in our database
    const data = readData()
    let user = data.users.find((u) => u.email === email)
    let needUsername = false

    if (user) {
      // Update existing user
      user.name = name
      user.avatar = picture
      user.lastLogin = new Date().toISOString()
      user.loyaltyPoints = user.loyaltyPoints || 0
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
        loyaltyPoints: 0,
      }
      data.users.push(user)
      needUsername = true
    }

    writeData(data)

    // Generate a JWT token for the user
    const jwtToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    })

    // Redirect to the frontend with user data
    if (needUsername) {
      res.redirect(
        `${FRONTEND_URL}/signin.html?token=${jwtToken}&email=${encodeURIComponent(email)}&name=${encodeURIComponent(name)}&avatar=${encodeURIComponent(picture)}&needUsername=true`,
      )
    } else {
      res.redirect(`${FRONTEND_URL}/index.html?token=${jwtToken}&email=${encodeURIComponent(email)}`)
    }
  } catch (error) {
    console.error("Google callback error:", error)
    res.redirect(`${FRONTEND_URL}/signin.html?error=auth_error`)
  }
})

// Authentication endpoints
app.post("/api/auth/google", async (req, res) => {
  try {
    const { token } = req.body

    if (!token) {
      return res.status(400).json({ error: "Token is required" })
    }

    const userData = await verifyGoogleToken(token)

    if (!userData) {
      return res.status(401).json({ error: "Invalid token" })
    }

    const { email, name, picture, email_verified } = userData

    if (!email_verified) {
      return res.status(401).json({ error: "Email not verified" })
    }

    // Check if user exists in our database
    const data = readData()
    let user = data.users.find((u) => u.email === email)

    if (user) {
      // Update existing user
      user.name = name
      user.avatar = picture
      user.lastLogin = new Date().toISOString()
      user.loyaltyPoints = user.loyaltyPoints || 0
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
        loyaltyPoints: 0,
      }
      data.users.push(user)
    }

    writeData(data)

    // Generate a JWT token for the user
    const jwtToken = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    })

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
        loyaltyPoints: user.loyaltyPoints,
      },
    })
  } catch (error) {
    console.error("Google authentication error:", error)
    res.status(500).json({ error: "Authentication failed", details: error.message })
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
      loyaltyPoints: user.loyaltyPoints || 0,
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
      loyaltyPoints: user.loyaltyPoints || 0,
    })
  } else {
    res.status(404).json({ error: "User not found" })
  }
})

// Add a new endpoint for youth parliament registration
app.post("/api/youth-parliament/register", (req, res) => {
  try {
    const { name, email, location, age, interests } = req.body

    if (!name || !email || !location) {
      return res.status(400).json({ error: "Name, email, and location are required" })
    }

    // In a real implementation, you would save this to a database
    // and send an email notification

    // Log the registration
    console.log("Youth Parliament Registration:", {
      name,
      email,
      location,
      age,
      interests,
      timestamp: new Date().toISOString(),
    })

    // Send confirmation email (mock implementation)
    console.log(`Sending confirmation email to ${email} and parliament@diplomaq.lol`)

    res.json({
      success: true,
      message: "Registration successful! We'll contact you with next steps.",
    })
  } catch (error) {
    console.error("Youth parliament registration error:", error)
    res.status(500).json({ error: "Registration failed", details: error.message })
  }
})

// Enhanced Ko-fi webhook endpoint
app.post("/api/kofi/webhook", (req, res) => {
  try {
    console.log("Received Ko-fi webhook:", req.body)

    // Extract data from the request
    const data = req.body.data || req.body

    // Verify Ko-fi verification token
    const expectedToken = "adbb7035-7f57-49ca-b3ee-5844ecb07a53"
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
        currency: currency || "GBP",
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
          const userData = readData()
          const user = userData.users.find((u) => u.email === email)

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
            user.loyaltyPoints = (user.loyaltyPoints || 0) + 20 // Add loyalty points

            user.payment_history.push({
              type: "subscription",
              tier: subscriptionTier,
              amount,
              currency,
              transaction_id: kofi_transaction_id,
              timestamp: new Date().toISOString(),
              loyaltyPointsEarned: 20,
            })

            writeData(userData)

            console.log(
              `Updated subscription for ${email} to ${subscriptionTier} and added 20 loyalty points. Total: ${user.loyaltyPoints}`,
            )

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
              loyaltyPointsEarned: 20,
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
              loyaltyPoints: 20, // Initial loyalty points
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
                  loyaltyPointsEarned: 20,
                },
              ],
            }

            const userData = readData()
            userData.users.push(newUser)
            writeData(userData)

            console.log(
              `Created new user with email ${email} and subscription ${newUser.subscription} and 20 loyalty points`,
            )

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
              loyaltyPointsEarned: 20,
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

            // Add loyalty points
            user.loyaltyPoints = (user.loyaltyPoints || 0) + 20

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

            console.log(`Added 20 loyalty points to ${email}. Total: ${user.loyaltyPoints}`)

            // Log transaction
            logTransaction({
              email,
              type: "Donation",
              amount,
              currency,
              kofi_transaction_id,
              timestamp,
              subscription_upgraded: tierRank[subscriptionTier] > tierRank[user.subscription],
              loyaltyPointsEarned: 20,
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
              loyaltyPoints: 20,
              last_donation: {
                amount,
                currency,
                timestamp: new Date().toISOString(),
                kofi_transaction_id,
              },
            }

            const userData = readData()
            userData.users.push(newUser)
            writeData(userData)

            console.log(`Created new user with email ${email} and 20 loyalty points`)
          }
        }
        break

      case "Shop Order":
        // Handle shop orders
        console.log("Shop order received:", shop_items)

        if (email) {
          const userData = readData()
          const user = userData.users.find((u) => u.email === email)

          if (user) {
            // Add loyalty points
            user.loyaltyPoints = (user.loyaltyPoints || 0) + 20
            user.shop_orders = user.shop_orders || []
            user.shop_orders.push({
              items: shop_items,
              amount,
              currency,
              transaction_id: kofi_transaction_id,
              timestamp: new Date().toISOString(),
              loyaltyPointsEarned: 20,
            })

            writeData(userData)
            console.log(`Added 20 loyalty points to ${email} for shop order. Total: ${user.loyaltyPoints}`)
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
              loyaltyPoints: 20,
              shop_orders: [
                {
                  items: shop_items,
                  amount,
                  currency,
                  transaction_id: kofi_transaction_id,
                  timestamp: new Date().toISOString(),
                  loyaltyPointsEarned: 20,
                },
              ],
            }

            const userData = readData()
            userData.users.push(newUser)
            writeData(userData)

            console.log(`Created new user with email ${email} and 20 loyalty points for shop order`)
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

// Add a user profile endpoint
app.get("/api/user/profile", (req, res) => {
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
    loyaltyPoints: user.loyaltyPoints || 0,
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
    loyaltyPoints: user.loyaltyPoints || 0,
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
    loyaltyPoints: user.loyaltyPoints || 0,
  })
})

// Loyalty points endpoint
app.get("/api/loyalty/points", (req, res) => {
  const { email } = req.query

  if (!email) {
    return res.status(400).json({ error: "Email is required" })
  }

  const data = readData()
  const user = data.users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: "User not found" })
  }

  res.json({
    loyaltyPoints: user.loyaltyPoints || 0,
    email: user.email,
    name: user.name,
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
