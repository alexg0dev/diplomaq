// Matchmaking module for Diplomaq.lol
const fs = require("fs-extra")
const path = require("path")
const crypto = require("crypto")

// File paths
const MATCHMAKING_FILE = path.join(__dirname, "matchmaking.json")
const DATA_FILE = path.join(__dirname, "data.json")
const DEBATES_FILE = path.join(__dirname, "debates.json")

// Pusher instance for real-time updates
let pusherInstance

// Matchmaking constants
const TIMEOUT_DURATION = 5 * 60 * 1000 // 5 minutes timeout (in milliseconds)
const CHECK_INTERVAL = 10 * 1000 // Check every 10 seconds
const CLEANUP_INTERVAL = 60 * 1000 // Cleanup every minute

// Quick match queue and active matches
let quickMatchRequests = []
const activeMatches = []

// Initialize the module
function init(pusher) {
  pusherInstance = pusher
  console.log("Matchmaking module initialized")

  // Ensure matchmaking file exists
  if (!fs.existsSync(MATCHMAKING_FILE)) {
    fs.writeJsonSync(MATCHMAKING_FILE, {
      queue: [],
      matches: [],
      quickMatches: [],
    })
  } else {
    // Load existing quick matches if file exists
    try {
      const matchmakingData = readMatchmaking()
      if (matchmakingData.quickMatches) {
        quickMatchRequests = matchmakingData.quickMatches
      }
    } catch (error) {
      console.error("Error loading quick matches:", error)
    }
  }

  // Start the periodic checking and cleanup
  startMatchmaking()
}

// Helper functions for file operations
function readMatchmaking() {
  try {
    return fs.readJsonSync(MATCHMAKING_FILE)
  } catch (error) {
    console.error("Error reading matchmaking file:", error)
    return { queue: [], matches: [], quickMatches: [] }
  }
}

function writeMatchmaking(data) {
  try {
    fs.writeJsonSync(MATCHMAKING_FILE, data)
    return true
  } catch (error) {
    console.error("Error writing to matchmaking file:", error)
    return false
  }
}

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

// Clean up expired queue entries (older than TIMEOUT_DURATION)
function cleanupExpiredEntries() {
  const matchmakingData = readMatchmaking()
  const now = new Date()
  const timeoutThreshold = new Date(now.getTime() - TIMEOUT_DURATION)

  // Get expired entries
  const expiredEntries = matchmakingData.queue.filter((entry) => new Date(entry.joinedAt) < timeoutThreshold)

  // For each expired entry, generate an AI debate if needed
  expiredEntries.forEach((entry) => {
    console.log(`Queue timeout for user: ${entry.email}`)

    // Generate AI debate for the user
    generateAIDebateForUser(entry)

    // Notify user about timeout
    if (pusherInstance) {
      pusherInstance.trigger(`user-${entry.userId}`, "queue-timeout", {
        timestamp: now.toISOString(),
        message: "No match found in time. An AI debate has been created for you.",
      })
    }
  })

  // Remove expired entries from queue
  matchmakingData.queue = matchmakingData.queue.filter((entry) => new Date(entry.joinedAt) >= timeoutThreshold)

  // Process quick match timeouts
  const expiredQuickMatches = quickMatchRequests.filter((request) => new Date(request.timestamp) < timeoutThreshold)

  // Process each expired quick match
  expiredQuickMatches.forEach((request) => {
    console.log(`Quick match timeout for user: ${request.email}`)

    // Generate AI debate for quick match
    generateAIDebateForUser({
      userId: request.userId,
      email: request.email,
      name: request.name,
      username: request.username,
      avatar: request.avatar,
      council: request.council || "UNGA",
      topic: request.topic,
    })

    // Notify user
    if (pusherInstance) {
      pusherInstance.trigger(`user-${request.userId}`, "quick-match-timeout", {
        timestamp: now.toISOString(),
        message: "No quick match found. An AI debate has been created for you.",
      })
    }
  })

  // Remove expired quick matches
  quickMatchRequests = quickMatchRequests.filter((request) => new Date(request.timestamp) >= timeoutThreshold)

  // Update matchmaking data with filtered quick matches
  matchmakingData.quickMatches = quickMatchRequests

  writeMatchmaking(matchmakingData)
}

// Generate an AI debate for a user who didn't find a match
function generateAIDebateForUser(user) {
  try {
    const userData = readData()
    const userRecord = userData.users.find((u) => u.id === user.userId || u.email === user.email)

    if (!userRecord) {
      console.error(`User not found for AI debate generation: ${user.email}`)
      return false
    }

    // Generate a random topic if one wasn't specified
    const topic = user.topic || getRandomTopic(user.council || "UNGA")

    // Create a new debate with AI
    const debateId = crypto.randomUUID()
    const newDebate = {
      id: debateId,
      title: `AI Debate: ${topic}`,
      description: `AI-generated debate on ${topic}`,
      council: user.council || "UNGA",
      topic: topic,
      status: "active",
      participants: [
        {
          id: userRecord.id,
          email: userRecord.email,
          name: userRecord.name || userRecord.email.split("@")[0],
          username: userRecord.username || userRecord.name || userRecord.email.split("@")[0],
          avatar: userRecord.avatar || "/placeholder.svg",
          joinedAt: new Date().toISOString(),
        },
        {
          id: "ai-assistant",
          email: "ai@diplomaq.lol",
          name: "AI Diplomat",
          username: "ai_diplomat",
          avatar: "/images/ai-avatar.png",
          joinedAt: new Date().toISOString(),
          isAI: true,
        },
      ],
      isAIDebate: true,
      createdAt: new Date().toISOString(),
      startTime: new Date().toISOString(),
      endTime: null,
    }

    // Add debate to debates file
    const debatesData = readDebates()
    debatesData.debates.push(newDebate)
    writeDebates(debatesData)

    // Update user stats
    userRecord.debatesJoined = (userRecord.debatesJoined || 0) + 1
    userRecord.debatesJoinedToday = (userRecord.debatesJoinedToday || 0) + 1
    userRecord.lastDebateJoinDate = new Date().toISOString()
    writeData(userData)

    // Notify user about the new AI debate
    if (pusherInstance) {
      pusherInstance.trigger(`user-${userRecord.id}`, "ai-debate-created", {
        debate: newDebate,
        message: "You've been matched with an AI diplomat.",
      })

      // Also trigger on the debates channel
      pusherInstance.trigger("debates", "debate-created", { debate: newDebate })

      // Generate an initial AI message
      setTimeout(() => {
        generateAIMessage(debateId, topic)
      }, 2000)
    }

    console.log(`AI debate created for user ${userRecord.email} on topic: ${topic}`)
    return true
  } catch (error) {
    console.error("Error generating AI debate:", error)
    return false
  }
}

// Generate an AI message in a debate
function generateAIMessage(debateId, topic) {
  try {
    // Read existing debates
    const debatesData = readDebates()
    const debate = debatesData.debates.find((d) => d.id === debateId)

    if (!debate) {
      console.error(`Debate not found for AI message: ${debateId}`)
      return
    }

    // Generate AI response based on topic
    const aiResponses = [
      `I welcome this opportunity to discuss ${topic}. As we begin, let's consider the global implications and potential solutions.`,
      `The issue of ${topic} requires careful consideration of both immediate challenges and long-term strategies.`,
      `When addressing ${topic}, we must balance sovereignty concerns with our collective responsibility to the international community.`,
      `The evidence suggests that a multilateral approach to ${topic} would yield the most sustainable outcomes.`,
      `My delegation proposes we examine ${topic} through the lens of sustainable development and equitable access to resources.`,
    ]

    const aiResponse = aiResponses[Math.floor(Math.random() * aiResponses.length)]

    // Create AI message
    const messageId = crypto.randomUUID()
    const aiMessage = {
      id: messageId,
      debateId: debateId,
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
    const messagesPath = path.join(__dirname, "messages.json")
    let messagesData

    if (fs.existsSync(messagesPath)) {
      messagesData = fs.readJsonSync(messagesPath)
    } else {
      messagesData = { messages: [] }
    }

    messagesData.messages.push(aiMessage)
    fs.writeJsonSync(messagesPath, messagesData)

    // Trigger Pusher event for real-time updates
    if (pusherInstance) {
      pusherInstance.trigger(`debate-${debateId}`, "new-message", aiMessage)
    }

    console.log(`AI message generated for debate ${debateId}`)
    return true
  } catch (error) {
    console.error("Error generating AI message:", error)
    return false
  }
}

// Join matchmaking queue
function joinQueue(userId, email, name, username, avatar, council, topic) {
  console.log(`User ${userId} (${email}) joined queue for ${council} council`)

  if (!userId || !email) {
    console.error("Missing required user information for queue")
    return {
      success: false,
      error: "Missing user information",
    }
  }

  // Find or create user record
  const userData = readData()
  let userRecord = userData.users.find((u) => u.id === userId || u.email === email)

  // If user not found, create a temporary user record
  if (!userRecord) {
    console.log(`User with email ${email} not found for matchmaking, creating temporary record`)
    userRecord = {
      id: userId || crypto.randomUUID(),
      email,
      name: name || email.split("@")[0],
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      debatesJoined: 0,
      debatesCreated: 0,
      debatesJoinedToday: 0,
    }

    userData.users.push(userRecord)
    writeData(userData)
  }

  const matchmakingData = readMatchmaking()

  // Check if user is already in queue
  const existingEntry = matchmakingData.queue.find((entry) => entry.userId === userId || entry.email === email)

  if (existingEntry) {
    return {
      success: false,
      error: "You are already in the matchmaking queue",
    }
  }

  // Get user's previous matches to avoid matching with the same people
  let previousMatches = []
  if (userRecord.previousMatches) {
    previousMatches = userRecord.previousMatches.map((match) => match.userId)
  }

  // Add user to queue
  const queueEntry = {
    userId: userRecord.id,
    email: userRecord.email,
    name: userRecord.name || email.split("@")[0],
    username: userRecord.username || userRecord.name || email.split("@")[0],
    avatar: userRecord.avatar || "/placeholder.svg",
    council,
    topic: topic || null,
    joinedAt: new Date().toISOString(),
    previousMatches,
  }

  matchmakingData.queue.push(queueEntry)
  writeMatchmaking(matchmakingData)

  // Trigger Pusher event to notify the user they've joined the queue
  if (pusherInstance) {
    pusherInstance.trigger(`user-${userRecord.id}`, "queue-joined", {
      council,
      topic,
      timestamp: new Date().toISOString(),
      queuePosition: matchmakingData.queue.length,
      queueSize: matchmakingData.queue.length,
    })
  }

  // Try to find a match
  const match = findMatch(queueEntry, matchmakingData.queue)

  if (match) {
    // Create a debate for the matched users
    const debate = createDebate(queueEntry, match)

    // Remove both users from queue
    matchmakingData.queue = matchmakingData.queue.filter(
      (entry) => entry.userId !== userRecord.id && entry.userId !== match.userId,
    )

    // Add to matches history
    matchmakingData.matches.push({
      debateId: debate.id,
      users: [userRecord.id, match.userId],
      council,
      topic: topic || match.topic || null,
      matchedAt: new Date().toISOString(),
    })

    writeMatchmaking(matchmakingData)

    // Update user stats and previous matches
    updateUserStats(userRecord.id, match.userId)

    return {
      success: true,
      matched: true,
      debate,
    }
  }

  return {
    success: true,
    matched: false,
    message: "You've been added to the matchmaking queue. We'll notify you when a match is found.",
  }
}

// Leave matchmaking queue
function leaveQueue(userId, email) {
  console.log(`User ${userId || email} left the queue`)

  if (!userId && !email) {
    return {
      success: false,
      error: "User ID or email is required",
    }
  }

  const matchmakingData = readMatchmaking()

  // Check if user is in queue
  const queueEntry = matchmakingData.queue.find((entry) => entry.userId === userId || entry.email === email)

  if (!queueEntry) {
    return {
      success: false,
      error: "You are not in the matchmaking queue",
    }
  }

  // Remove user from queue
  matchmakingData.queue = matchmakingData.queue.filter((entry) => entry.userId !== userId && entry.email !== email)

  // Also remove from quick match if present
  if (userId) {
    quickMatchRequests = quickMatchRequests.filter((request) => request.userId !== userId)
    matchmakingData.quickMatches = quickMatchRequests
  } else if (email) {
    quickMatchRequests = quickMatchRequests.filter((request) => request.email !== email)
    matchmakingData.quickMatches = quickMatchRequests
  }

  writeMatchmaking(matchmakingData)

  // Trigger Pusher event to notify the user they've left the queue
  if (pusherInstance && userId) {
    pusherInstance.trigger(`user-${userId}`, "queue-left", {
      timestamp: new Date().toISOString(),
    })
  }

  return { success: true }
}

// Get queue status for a user
function getQueueStatus(userId, email) {
  if (!userId && !email) {
    return {
      success: false,
      error: "User ID or email is required",
    }
  }

  const matchmakingData = readMatchmaking()

  // Check if user is in queue
  let queueIndex = -1

  if (userId) {
    queueIndex = matchmakingData.queue.findIndex((entry) => entry.userId === userId)
  } else if (email) {
    queueIndex = matchmakingData.queue.findIndex((entry) => entry.email === email)
  }

  if (queueIndex === -1) {
    // Check if user is in quick match
    const quickMatch = quickMatchRequests.find(
      (request) => (userId && request.userId === userId) || (email && request.email === email),
    )

    if (quickMatch) {
      return {
        inQueue: false,
        inQuickMatch: true,
        quickMatchRequest: quickMatch,
        timestamp: quickMatch.timestamp,
      }
    }

    return {
      inQueue: false,
      inQuickMatch: false,
    }
  }

  // Get any recent matches for this user
  const recentMatches = matchmakingData.matches.filter(
    (match) => match.users.includes(userId) && new Date(match.matchedAt) > new Date(Date.now() - 60 * 1000), // Matches in the last minute
  )

  if (recentMatches.length > 0) {
    const mostRecentMatch = recentMatches[recentMatches.length - 1]

    // Look up the debate
    const debatesData = readDebates()
    const debate = debatesData.debates.find((d) => d.id === mostRecentMatch.debateId)

    if (debate) {
      return {
        inQueue: false,
        matched: true,
        debate: debate,
      }
    }
  }

  return {
    inQueue: true,
    queueEntry: matchmakingData.queue[queueIndex],
    queuePosition: queueIndex + 1,
    queueSize: matchmakingData.queue.length,
  }
}

// Add function to handle quick match requests
function requestQuickMatch(userId, email, name, username, avatar, council, topic) {
  console.log(`Quick match request from user ${userId || email} for ${council} council`)

  if (!userId && !email) {
    return {
      success: false,
      error: "User ID or email is required",
    }
  }

  // Find or create user record
  const userData = readData()
  let userRecord = userData.users.find((u) => u.id === userId || u.email === email)

  // If user not found, create a temporary user record
  if (!userRecord) {
    console.log(`User with email ${email} not found for quick match, creating temporary record`)
    userRecord = {
      id: userId || crypto.randomUUID(),
      email,
      name: name || email.split("@")[0],
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      debatesJoined: 0,
      debatesCreated: 0,
      debatesJoinedToday: 0,
    }

    userData.users.push(userRecord)
    writeData(userData)
    userId = userRecord.id
  }

  // Check if this user already has a quick match request
  const existingRequest = quickMatchRequests.find((request) => request.userId === userId || request.email === email)

  if (existingRequest) {
    // Update the existing request
    existingRequest.timestamp = new Date().toISOString()
    existingRequest.council = council || existingRequest.council
    existingRequest.topic = topic || existingRequest.topic
  } else {
    // Add new quick match request
    quickMatchRequests.push({
      userId: userId,
      email: email,
      name: name || userRecord.name || email.split("@")[0],
      username: username || userRecord.username || name || email.split("@")[0],
      avatar: avatar || userRecord.avatar || "/placeholder.svg",
      council: council || "UNGA",
      topic: topic,
      timestamp: new Date().toISOString(),
    })
  }

  // Save quick match requests
  const matchmakingData = readMatchmaking()
  matchmakingData.quickMatches = quickMatchRequests
  writeMatchmaking(matchmakingData)

  // Find a match immediately if possible
  const match = findQuickMatch(userId, email)

  if (match) {
    // Create a debate between these users
    const userEntry = {
      userId: userId,
      email: email,
      name: name || userRecord.name || email.split("@")[0],
      username: username || userRecord.username || name || email.split("@")[0],
      avatar: avatar || userRecord.avatar || "/placeholder.svg",
      council: council || "UNGA",
      topic: topic,
    }

    const debate = createDebate(userEntry, match)

    // Remove both users from quick match queue
    quickMatchRequests = quickMatchRequests.filter(
      (request) =>
        request.userId !== userId &&
        request.userId !== match.userId &&
        request.email !== email &&
        request.email !== match.email,
    )

    // Update matchmaking data
    matchmakingData.quickMatches = quickMatchRequests

    // Add to matches history
    matchmakingData.matches.push({
      debateId: debate.id,
      users: [userId, match.userId],
      council: council || match.council || "UNGA",
      topic: topic || match.topic || null,
      matchedAt: new Date().toISOString(),
      quickMatch: true,
    })

    writeMatchmaking(matchmakingData)

    // Update user stats
    updateUserStats(userId, match.userId)

    return {
      success: true,
      matched: true,
      debate: debate,
    }
  }

  return {
    success: true,
    matched: false,
    message: "Quick match request received. Looking for a match...",
  }
}

// Find a quick match partner
function findQuickMatch(userId, email) {
  // Filter out the current user
  const potentialMatches = quickMatchRequests.filter((request) => {
    return request.userId !== userId && request.email !== email
  })

  if (potentialMatches.length === 0) {
    return null
  }

  // Find the oldest request
  potentialMatches.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
  return potentialMatches[0]
}

// Check for quick matches periodically
function checkQuickMatches() {
  if (quickMatchRequests.length <= 1) {
    return // Not enough people for matching
  }

  const processedUsers = new Set()
  const matchmakingData = readMatchmaking()
  let matchesFound = false

  // Try to match each user
  for (const request of quickMatchRequests) {
    // Skip if already processed
    if (processedUsers.has(request.userId)) continue

    // Find a match
    const match = findQuickMatch(request.userId, request.email)

    if (match && !processedUsers.has(match.userId)) {
      processedUsers.add(request.userId)
      processedUsers.add(match.userId)

      // Create a debate between these users
      const debate = createDebate(request, match)

      // Add to matches history
      matchmakingData.matches.push({
        debateId: debate.id,
        users: [request.userId, match.userId],
        council: request.council || match.council || "UNGA",
        topic: request.topic || match.topic || null,
        matchedAt: new Date().toISOString(),
        quickMatch: true,
      })

      // Update user stats
      updateUserStats(request.userId, match.userId)

      matchesFound = true
    }
  }

  // Remove matched users from quick match queue
  if (matchesFound) {
    quickMatchRequests = quickMatchRequests.filter((request) => !processedUsers.has(request.userId))

    matchmakingData.quickMatches = quickMatchRequests
    writeMatchmaking(matchmakingData)
  }
}

// Find a match for a user
function findMatch(user, queue) {
  // Filter out potential matches
  const potentialMatches = queue.filter((entry) => {
    // Don't match with self
    if (entry.userId === user.userId || entry.email === user.email) return false

    // Must be same council
    if (entry.council !== user.council) return false

    // Check if users have been matched before (avoid matching with same users if possible)
    if (user.previousMatches && user.previousMatches.includes(entry.userId)) {
      // Only avoid previous matches if there are other options
      const otherOptions = queue.some(
        (e) =>
          e.userId !== user.userId &&
          e.userId !== entry.userId &&
          e.council === user.council &&
          (!user.previousMatches || !user.previousMatches.includes(e.userId)),
      )

      if (otherOptions) return false
    }

    // If both users specified a topic, they should match on topic
    if (user.topic && entry.topic && user.topic !== entry.topic) {
      // Only enforce topic match if there are other options with the same topic
      const sameTopicMatches = queue.some(
        (e) => e.userId !== user.userId && e.council === user.council && e.topic === user.topic,
      )

      if (sameTopicMatches) return false
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

// Create a debate for matched users
function createDebate(user1, user2) {
  // Determine the topic
  const topic = user1.topic || user2.topic || getRandomTopic(user1.council || "UNGA")

  const debateId = crypto.randomUUID()
  const newDebate = {
    id: debateId,
    title: `Debate: ${topic}`,
    description: `A matched debate on ${topic} between delegates.`,
    council: user1.council || user2.council || "UNGA",
    topic,
    status: "active",
    participants: [
      {
        id: user1.userId,
        email: user1.email,
        name: user1.name,
        username: user1.username || user1.name,
        avatar: user1.avatar || "/placeholder.svg",
        joinedAt: new Date().toISOString(),
      },
      {
        id: user2.userId,
        email: user2.email,
        name: user2.name,
        username: user2.username || user2.name,
        avatar: user2.avatar || "/placeholder.svg",
        joinedAt: new Date().toISOString(),
      },
    ],
    isMatchmade: true,
    createdAt: new Date().toISOString(),
    startTime: new Date().toISOString(),
    endTime: null,
    votes: {},
    userVotes: {},
  }

  // Add debate to debates file
  const debatesData = readDebates()
  debatesData.debates.push(newDebate)
  writeDebates(debatesData)

  // Notify both users
  if (pusherInstance) {
    pusherInstance.trigger(`user-${user1.userId}`, "match-found", { debate: newDebate })
    pusherInstance.trigger(`user-${user2.userId}`, "match-found", { debate: newDebate })
    pusherInstance.trigger("debates", "debate-created", { debate: newDebate })

    // Also trigger a specific event for the debates page to remove this debate
    pusherInstance.trigger("debates", "debate-matched", {
      debateId: debateId,
      participantIds: [user1.userId, user2.userId],
    })
  }

  console.log(`Created debate ${debateId} between ${user1.email} and ${user2.email} on topic: ${topic}`)
  return newDebate
}

// Update user stats after a match
function updateUserStats(userId1, userId2) {
  try {
    const data = readData()

    // Update first user if found
    const user1 = data.users.find((u) => u.id === userId1)
    if (user1) {
      user1.debatesJoined = (user1.debatesJoined || 0) + 1
      user1.debatesJoinedToday = (user1.debatesJoinedToday || 0) + 1
      user1.lastDebateJoinDate = new Date().toISOString()

      // Track previous match
      if (!user1.previousMatches) {
        user1.previousMatches = []
      }
      user1.previousMatches.push({
        userId: userId2,
        timestamp: new Date().toISOString(),
      })

      // Limit previous matches history to last 20
      if (user1.previousMatches.length > 20) {
        user1.previousMatches = user1.previousMatches.slice(-20)
      }
    } else {
      console.warn(`User with ID ${userId1} not found for stats update`)
    }

    // Update second user if found
    const user2 = data.users.find((u) => u.id === userId2)
    if (user2) {
      user2.debatesJoined = (user2.debatesJoined || 0) + 1
      user2.debatesJoinedToday = (user2.debatesJoinedToday || 0) + 1
      user2.lastDebateJoinDate = new Date().toISOString()

      // Track previous match
      if (!user2.previousMatches) {
        user2.previousMatches = []
      }
      user2.previousMatches.push({
        userId: userId1,
        timestamp: new Date().toISOString(),
      })

      // Limit previous matches history to last 20
      if (user2.previousMatches.length > 20) {
        user2.previousMatches = user2.previousMatches.slice(-20)
      }
    } else {
      console.warn(`User with ID ${userId2} not found for stats update`)
    }

    writeData(data)
    return true
  } catch (error) {
    console.error("Error updating user stats:", error)
    return false
  }
}

// Get topics for a specific council
function getRandomTopic(council) {
  const topics = {
    UNSC: [
      "Cybersecurity and International Peace",
      "Nuclear Non-Proliferation",
      "Terrorism and International Security",
      "Protection of Civilians in Armed Conflict",
      "Climate Change as a Security Threat",
      "Peacekeeping Operations Reform",
      "Women, Peace, and Security",
      "Maritime Security and Piracy",
      "Sanctions Regimes Effectiveness",
      "Conflict Prevention in Fragile States",
    ],
    UNGA: [
      "Sustainable Development Goals Implementation",
      "Global Health Security",
      "Digital Divide and Technology Transfer",
      "Outer Space Governance",
      "Global Tax Reform",
      "Artificial Intelligence Governance",
      "Plastic Pollution in Oceans",
      "Global Education Crisis",
      "Aging Populations and Social Security",
      "Indigenous Peoples' Rights",
    ],
    UNHRC: [
      "Digital Rights and Privacy",
      "Business and Human Rights",
      "Rights of Persons with Disabilities",
      "Freedom of Religion or Belief",
      "Human Rights Defenders Protection",
      "Death Penalty Moratorium",
      "Human Rights and Climate Change",
      "Racial Discrimination and Xenophobia",
      "Freedom of Assembly and Association",
      "Human Rights in Counterterrorism",
    ],
  }

  // Get topics for the council or use UNGA as default
  const councilTopics = topics[council] || topics.UNGA

  // Select random topic
  return councilTopics[Math.floor(Math.random() * councilTopics.length)]
}

// Check for matches periodically
function checkForMatches() {
  const matchmakingData = readMatchmaking()

  // Skip if queue is empty or has only one user
  if (matchmakingData.queue.length <= 1) {
    return
  }

  let matchesFound = false
  const processedUsers = new Set()

  // Try to match each user in the queue
  for (const user of matchmakingData.queue) {
    // Skip if user has already been matched in this iteration
    if (processedUsers.has(user.userId)) continue

    const match = findMatch(
      user,
      matchmakingData.queue.filter((e) => !processedUsers.has(e.userId)),
    )

    if (match && !processedUsers.has(match.userId)) {
      processedUsers.add(user.userId)
      processedUsers.add(match.userId)

      // Create a debate for the matched users
      const debate = createDebate(user, match)

      // Add to matches history
      matchmakingData.matches.push({
        debateId: debate.id,
        users: [user.userId, match.userId],
        council: user.council,
        topic: user.topic || match.topic || null,
        matchedAt: new Date().toISOString(),
      })

      // Update user stats and previous matches
      updateUserStats(user.userId, match.userId)

      matchesFound = true
    }
  }

  if (matchesFound) {
    // Remove matched users from queue
    matchmakingData.queue = matchmakingData.queue.filter((entry) => !processedUsers.has(entry.userId))

    writeMatchmaking(matchmakingData)
  }
}

// Start periodic match checking and cleanup
function startMatchmaking() {
  // Check for matches every 10 seconds
  setInterval(checkForMatches, CHECK_INTERVAL)

  // Check for quick matches every 5 seconds
  setInterval(checkQuickMatches, CHECK_INTERVAL / 2)

  // Clean up expired entries every minute
  setInterval(cleanupExpiredEntries, CLEANUP_INTERVAL)

  console.log("Matchmaking system started")
}

// Export the module functions
module.exports = {
  init,
  joinQueue,
  leaveQueue,
  getQueueStatus,
  findMatch,
  createDebate,
  requestQuickMatch,
  generateAIDebateForUser,
  startMatchmaking,
}
