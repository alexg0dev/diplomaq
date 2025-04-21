// Debate Handler for Diplomaq.lol
const fs = require("fs-extra")
const path = require("path")
const crypto = require("crypto")

// File paths
const DATA_FILE = path.join(__dirname, "data.json")
const DEBATES_FILE = path.join(__dirname, "debates.json")
const MESSAGES_FILE = path.join(__dirname, "messages.json")

// Constants
const MAX_DEBATE_DURATION = 35 * 60 // 35 minutes in seconds
const MESSAGE_COOLDOWN = 2000 // 2 seconds between messages
const ALLOWED_COUNCILS = ["UNSC", "UNGA", "UNHRC", "ECOSOC"] // Only UN councils, no WHO

// Helper functions for file operations
function readData() {
  try {
    return fs.readJsonSync(DATA_FILE)
  } catch (error) {
    console.error("Error reading data file:", error)
    return { users: [] }
  }
}

function writeData(data) {
  try {
    fs.writeJsonSync(DATA_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to data file:", error)
    return false
  }
}

function readDebates() {
  try {
    return fs.readJsonSync(DEBATES_FILE)
  } catch (error) {
    console.error("Error reading debates file:", error)
    return { debates: [] }
  }
}

function writeDebates(data) {
  try {
    fs.writeJsonSync(DEBATES_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to debates file:", error)
    return false
  }
}

function readMessages() {
  try {
    return fs.readJsonSync(MESSAGES_FILE)
  } catch (error) {
    console.error("Error reading messages file:", error)
    return { messages: [] }
  }
}

function writeMessages(data) {
  try {
    fs.writeJsonSync(MESSAGES_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to messages file:", error)
    return false
  }
}

// User management functions
function getUser(email) {
  const data = readData()
  return data.users.find((user) => user.email === email)
}

function updateUser(user) {
  const data = readData()
  const index = data.users.findIndex((u) => u.email === user.email)

  if (index !== -1) {
    data.users[index] = user
    writeData(data)
    return true
  }

  return false
}

function createUser(email, name, username, avatar) {
  const data = readData()

  // Check if user already exists
  if (data.users.some((user) => user.email === email)) {
    return false
  }

  // Create new user
  const newUser = {
    id: crypto.randomUUID(),
    email,
    name: name || email.split("@")[0],
    username: username || name || email.split("@")[0],
    avatar: avatar || "/placeholder.svg",
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
    debatesJoined: 0,
    debatesCreated: 0,
    activeDebateId: null,
    debateHistory: [],
    lastMessageTime: 0,
  }

  data.users.push(newUser)
  writeData(data)

  return newUser
}

function getOrCreateUser(email, name, username, avatar) {
  let user = getUser(email)

  if (!user) {
    user = createUser(email, name, username, avatar)
  } else {
    // Update last login
    user.lastLogin = new Date().toISOString()

    // Update username if provided and not already set
    if (username && !user.username) {
      user.username = username
    }

    // Update avatar if provided
    if (avatar) {
      user.avatar = avatar
    }

    updateUser(user)
  }

  return user
}

// Debate management functions
function createDebate(title, description, council, topic, email) {
  // Validate council
  if (!ALLOWED_COUNCILS.includes(council)) {
    return { success: false, error: "Invalid council. Only UN councils are allowed." }
  }

  const user = getUser(email)

  if (!user) {
    // Create user if not found
    const user = getOrCreateUser(email, null, null, null)
    if (!user) {
      return { success: false, error: "Failed to create user" }
    }
  }

  // Check if user is already in a debate
  if (user.activeDebateId) {
    return {
      success: false,
      error: "You are already in an active debate. Please leave your current debate before creating a new one.",
    }
  }

  // Create new debate
  const debateId = crypto.randomUUID()
  const now = new Date().toISOString()

  const newDebate = {
    id: debateId,
    title,
    description,
    council,
    topic: topic || "General",
    status: "active",
    participants: [
      {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        avatar: user.avatar,
        joinedAt: now,
        isCreator: true,
      },
    ],
    createdBy: user.id,
    createdAt: now,
    startTime: now,
    endTime: null,
    expiresAt: new Date(Date.now() + MAX_DEBATE_DURATION * 1000).toISOString(),
    timerStarted: false, // Add flag to track if timer has started
    timerStartTime: null, // Add timestamp for when timer started
  }

  // Update debates file
  const debatesData = readDebates()
  debatesData.debates.push(newDebate)
  writeDebates(debatesData)

  // Update user
  user.debatesCreated += 1
  user.debatesJoined += 1
  user.activeDebateId = debateId
  updateUser(user)

  return { success: true, debate: newDebate }
}

function joinDebate(debateId, email) {
  const user = getUser(email)

  if (!user) {
    // Create user if not found
    const newUser = getOrCreateUser(email, null, null, null)
    if (!newUser) {
      return { success: false, error: "Failed to create user" }
    }
    return joinDebate(debateId, email) // Retry with the new user
  }

  // Check if user is already in a debate
  if (user.activeDebateId && user.activeDebateId !== debateId) {
    return {
      success: false,
      error: "You are already in an active debate. Please leave your current debate before joining a new one.",
    }
  }

  // Get debate
  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === debateId)

  if (!debate) {
    return { success: false, error: "Debate not found" }
  }

  // Check if debate is active
  if (debate.status !== "active") {
    return { success: false, error: "This debate is not currently active" }
  }

  // Check if debate has expired
  if (debate.expiresAt && new Date(debate.expiresAt) < new Date()) {
    debate.status = "expired"
    writeDebates(debatesData)
    return { success: false, error: "This debate has expired" }
  }

  // Check if user is already a participant
  if (debate.participants.some((p) => p.email === email)) {
    // User is already a participant, just update their active debate ID
    user.activeDebateId = debateId
    updateUser(user)

    return { success: true, debate, alreadyJoined: true }
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

  // If this is the second participant, start the timer
  if (debate.participants.length === 2 && !debate.timerStarted) {
    debate.timerStarted = true
    debate.timerStartTime = new Date().toISOString()
  }

  // Update debates file
  writeDebates(debatesData)

  // Update user
  user.debatesJoined += 1
  user.activeDebateId = debateId
  updateUser(user)

  return { success: true, debate }
}

function leaveDebate(debateId, email, saveToProfile = false) {
  const user = getUser(email)

  if (!user) {
    return { success: false, error: "User not found" }
  }

  // Check if user is in this debate
  if (user.activeDebateId !== debateId) {
    return { success: false, error: "You are not in this debate" }
  }

  // Get debate
  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === debateId)

  if (!debate) {
    return { success: false, error: "Debate not found" }
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

  // Update user
  user.activeDebateId = null

  // Save to profile if requested
  if (saveToProfile) {
    if (!user.debateHistory) {
      user.debateHistory = []
    }

    user.debateHistory.push({
      debateId,
      title: debate.title,
      council: debate.council,
      topic: debate.topic,
      joinedAt: debate.participants.find((p) => p.email === email)?.joinedAt || debate.startTime,
      leftAt: new Date().toISOString(),
    })
  }

  updateUser(user)

  return { success: true }
}

function saveDebateToProfile(debateId, email) {
  const user = getUser(email)

  if (!user) {
    return { success: false, error: "User not found" }
  }

  // Get debate
  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === debateId)

  if (!debate) {
    return { success: false, error: "Debate not found" }
  }

  // Check if debate is already in user's history
  if (user.debateHistory && user.debateHistory.some((d) => d.debateId === debateId)) {
    return { success: false, error: "Debate already saved to profile" }
  }

  // Add to user's debate history
  if (!user.debateHistory) {
    user.debateHistory = []
  }

  const userParticipant = debate.participants.find((p) => p.email === email)

  user.debateHistory.push({
    debateId,
    title: debate.title,
    council: debate.council,
    topic: debate.topic,
    joinedAt: userParticipant?.joinedAt || debate.startTime,
    leftAt: new Date().toISOString(),
  })

  updateUser(user)

  return { success: true }
}

function sendMessage(debateId, email, content) {
  const user = getUser(email)

  if (!user) {
    return { success: false, error: "User not found" }
  }

  // Check if user is in this debate
  if (user.activeDebateId !== debateId) {
    return { success: false, error: "You are not in this debate" }
  }

  // Check for spam
  const now = Date.now()
  if (user.lastMessageTime && now - user.lastMessageTime < MESSAGE_COOLDOWN) {
    return { success: false, error: "Please wait before sending another message" }
  }

  // Get debate
  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === debateId)

  if (!debate) {
    return { success: false, error: "Debate not found" }
  }

  // Check if debate is active
  if (debate.status !== "active") {
    return { success: false, error: "This debate is not currently active" }
  }

  // Check if debate has expired
  if (debate.expiresAt && new Date(debate.expiresAt) < new Date()) {
    debate.status = "expired"
    debate.endTime = new Date().toISOString()
    writeDebates(debatesData)
    return { success: false, error: "This debate has expired" }
  }

  // Check if there are at least 2 participants
  if (debate.participants.length < 2) {
    return { success: false, error: "You need at least 2 participants to start messaging" }
  }

  // Create message
  const messageId = crypto.randomUUID()
  const newMessage = {
    id: messageId,
    debateId,
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

  // Update user's last message time
  user.lastMessageTime = now
  updateUser(user)

  return { success: true, message: newMessage }
}

function getMessages(debateId) {
  const messagesData = readMessages()
  return messagesData.messages.filter((m) => m.debateId === debateId)
}

function getDebateTimer(debateId) {
  const debatesData = readDebates()
  const debate = debatesData.debates.find((d) => d.id === debateId)

  if (!debate) {
    return { success: false, error: "Debate not found" }
  }

  // If timer hasn't started yet (less than 2 participants)
  if (!debate.timerStarted || !debate.timerStartTime) {
    return {
      success: true,
      timerStarted: false,
      timeRemaining: MAX_DEBATE_DURATION,
    }
  }

  // Calculate remaining time
  const startTime = new Date(debate.timerStartTime).getTime()
  const now = Date.now()
  const elapsedSeconds = Math.floor((now - startTime) / 1000)
  const remainingSeconds = Math.max(0, MAX_DEBATE_DURATION - elapsedSeconds)

  return {
    success: true,
    timerStarted: true,
    timeRemaining: remainingSeconds,
    startTime: debate.timerStartTime,
  }
}

function checkDebateExpiry() {
  const debatesData = readDebates()
  let updated = false

  debatesData.debates.forEach((debate) => {
    // If timer has started, check based on timer start time
    if (debate.status === "active" && debate.timerStarted && debate.timerStartTime) {
      const startTime = new Date(debate.timerStartTime).getTime()
      const now = Date.now()
      const elapsedSeconds = Math.floor((now - startTime) / 1000)

      if (elapsedSeconds >= MAX_DEBATE_DURATION) {
        debate.status = "expired"
        debate.endTime = new Date().toISOString()
        updated = true

        // Notify users that the debate has expired
        debate.participants.forEach((participant) => {
          const user = getUser(participant.email)
          if (user && user.activeDebateId === debate.id) {
            user.activeDebateId = null
            updateUser(user)
          }
        })
      }
    }
    // Also check the old way for backwards compatibility
    else if (debate.status === "active" && debate.expiresAt && new Date(debate.expiresAt) < new Date()) {
      debate.status = "expired"
      debate.endTime = new Date().toISOString()
      updated = true

      // Notify users that the debate has expired
      debate.participants.forEach((participant) => {
        const user = getUser(participant.email)
        if (user && user.activeDebateId === debate.id) {
          user.activeDebateId = null
          updateUser(user)
        }
      })
    }
  })

  if (updated) {
    writeDebates(debatesData)
  }
}

// Run debate expiry check every minute
setInterval(checkDebateExpiry, 60 * 1000)

// Export functions
module.exports = {
  getUser,
  getOrCreateUser,
  updateUser,
  createDebate,
  joinDebate,
  leaveDebate,
  saveDebateToProfile,
  sendMessage,
  getMessages,
  getDebateTimer,
  checkDebateExpiry,
  ALLOWED_COUNCILS,
  MAX_DEBATE_DURATION,
}
