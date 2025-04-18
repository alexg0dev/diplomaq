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

// Initialize the module with Pusher instance
function init(pusher) {
  pusherInstance = pusher
  console.log("Matchmaking module initialized")

  // Ensure matchmaking file exists
  if (!fs.existsSync(MATCHMAKING_FILE)) {
    fs.writeJsonSync(MATCHMAKING_FILE, {
      queue: [],
      matches: [],
    })
  }

  // Clean up expired queue entries on startup
  cleanupExpiredEntries()
}

// Helper functions for file operations
function readMatchmaking() {
  try {
    return fs.readJsonSync(MATCHMAKING_FILE)
  } catch (error) {
    console.error("Error reading matchmaking file:", error)
    return { queue: [], matches: [] }
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

// Clean up expired queue entries (older than 5 minutes)
function cleanupExpiredEntries() {
  const matchmakingData = readMatchmaking()
  const now = new Date()
  const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000)

  // Filter out entries older than 5 minutes
  const expiredEntries = matchmakingData.queue.filter((entry) => new Date(entry.joinedAt) < fiveMinutesAgo)

  // Notify users who were removed due to timeout
  expiredEntries.forEach((entry) => {
    if (pusherInstance) {
      pusherInstance.trigger(`user-${entry.userId}`, "queue-timeout", {
        timestamp: now.toISOString(),
      })
    }
  })

  // Remove expired entries
  matchmakingData.queue = matchmakingData.queue.filter((entry) => new Date(entry.joinedAt) >= fiveMinutesAgo)

  writeMatchmaking(matchmakingData)

  // Schedule next cleanup
  setTimeout(cleanupExpiredEntries, 60 * 1000) // Run every minute
}

// Join matchmaking queue
function joinQueue(userId, email, name, username, avatar, council, topic) {
  console.log(`User ${userId} joined queue for ${council} council`)

  const matchmakingData = readMatchmaking()

  // Check if user is already in queue
  const existingEntry = matchmakingData.queue.find((entry) => entry.userId === userId)
  if (existingEntry) {
    return {
      success: false,
      error: "You are already in the matchmaking queue",
    }
  }

  // Get user's previous matches to avoid matching with the same people
  const userData = readData()
  const user = userData.users.find((u) => u.id === userId)
  const previousMatches = user?.previousMatches || []

  // Add user to queue
  const queueEntry = {
    userId,
    email,
    name,
    username,
    avatar,
    council,
    topic: topic || null,
    joinedAt: new Date().toISOString(),
    previousMatches: previousMatches.map((match) => match.userId),
  }

  matchmakingData.queue.push(queueEntry)
  writeMatchmaking(matchmakingData)

  // Trigger Pusher event to notify the user they've joined the queue
  if (pusherInstance) {
    pusherInstance.trigger(`user-${userId}`, "queue-joined", {
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
      (entry) => entry.userId !== userId && entry.userId !== match.userId,
    )

    // Add to matches history
    matchmakingData.matches.push({
      debateId: debate.id,
      users: [userId, match.userId],
      council,
      topic: topic || match.topic || null,
      matchedAt: new Date().toISOString(),
    })

    writeMatchmaking(matchmakingData)

    // Update user stats and previous matches
    updateUserStats(userId, match.userId)

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
function leaveQueue(userId) {
  console.log(`User ${userId} left the queue`)

  const matchmakingData = readMatchmaking()

  // Check if user is in queue
  const queueEntry = matchmakingData.queue.find((entry) => entry.userId === userId)
  if (!queueEntry) {
    return {
      success: false,
      error: "You are not in the matchmaking queue",
    }
  }

  // Remove user from queue
  matchmakingData.queue = matchmakingData.queue.filter((entry) => entry.userId !== userId)
  writeMatchmaking(matchmakingData)

  // Trigger Pusher event to notify the user they've left the queue
  if (pusherInstance) {
    pusherInstance.trigger(`user-${userId}`, "queue-left", {
      timestamp: new Date().toISOString(),
    })
  }

  return { success: true }
}

// Get queue status for a user
function getQueueStatus(userId) {
  const matchmakingData = readMatchmaking()

  // Check if user is in queue
  const queueIndex = matchmakingData.queue.findIndex((entry) => entry.userId === userId)

  if (queueIndex === -1) {
    return {
      inQueue: false,
    }
  }

  return {
    inQueue: true,
    queueEntry: matchmakingData.queue[queueIndex],
    queuePosition: queueIndex + 1,
    queueSize: matchmakingData.queue.length,
  }
}

// Find a match for a user
function findMatch(user, queue) {
  // Filter out potential matches
  const potentialMatches = queue.filter((entry) => {
    // Don't match with self
    if (entry.userId === user.userId) return false

    // Must be same council
    if (entry.council !== user.council) return false

    // Check if users have been matched before (avoid matching with same users)
    if (user.previousMatches && user.previousMatches.includes(entry.userId)) return false
    if (entry.previousMatches && entry.previousMatches.includes(user.userId)) return false

    // If both users specified a topic, they should match on topic
    if (user.topic && entry.topic && user.topic !== entry.topic) return false

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
  const debateId = crypto.randomUUID()
  const topic = user1.topic || user2.topic || `${user1.council} Debate`

  const newDebate = {
    id: debateId,
    title: `Matched Debate: ${topic}`,
    description: `A matched debate on ${user1.council} topics.`,
    council: user1.council,
    topic,
    status: "active",
    participants: [
      {
        id: user1.userId,
        email: user1.email,
        name: user1.name,
        username: user1.username,
        avatar: user1.avatar,
        joinedAt: new Date().toISOString(),
      },
      {
        id: user2.userId,
        email: user2.email,
        name: user2.name,
        username: user2.username,
        avatar: user2.avatar,
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
  }

  return newDebate
}

// Update user stats after a match
function updateUserStats(userId1, userId2) {
  const data = readData()

  // Update first user
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
  }

  // Update second user
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
  }

  writeData(data)
}

// Get topics for a specific council
function getTopicsForCouncil(council) {
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

  return topics[council] || []
}

// Check for matches periodically
function checkForMatches() {
  const matchmakingData = readMatchmaking()

  // Skip if queue is empty or has only one user
  if (matchmakingData.queue.length <= 1) {
    return
  }

  let matchesFound = false

  // Try to match each user in the queue
  for (let i = 0; i < matchmakingData.queue.length; i++) {
    const user = matchmakingData.queue[i]

    // Skip if user has already been matched
    if (!user) continue

    const match = findMatch(user, matchmakingData.queue)

    if (match) {
      // Create a debate for the matched users
      const debate = createDebate(user, match)

      // Remove both users from queue
      matchmakingData.queue = matchmakingData.queue.filter(
        (entry) => entry.userId !== user.userId && entry.userId !== match.userId,
      )

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

      // Adjust index since we removed elements
      i--
    }
  }

  if (matchesFound) {
    writeMatchmaking(matchmakingData)
  }
}

// Start periodic match checking
function startMatchmaking() {
  // Check for matches every 10 seconds
  setInterval(checkForMatches, 10000)

  // Clean up expired entries every minute
  setInterval(cleanupExpiredEntries, 60000)
}

// Export the module functions
module.exports = {
  init,
  joinQueue,
  leaveQueue,
  getQueueStatus,
  findMatch,
  createDebate,
  getTopicsForCouncil,
  startMatchmaking,
}
