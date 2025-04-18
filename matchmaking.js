// Matchmaking module for Diplomaq.lol
let pusherInstance

// Initialize the module with Pusher instance
function init(pusher) {
  pusherInstance = pusher
  console.log("Matchmaking module initialized")
}

// Join matchmaking queue
function joinQueue(userId, council, topic) {
  console.log(`User ${userId} joined queue for ${council} council`)

  // Trigger Pusher event to notify the user they've joined the queue
  if (pusherInstance) {
    pusherInstance.trigger(`user-${userId}`, "queue-joined", {
      council,
      topic,
      timestamp: new Date().toISOString(),
    })
  }

  return { success: true }
}

// Leave matchmaking queue
function leaveQueue(userId) {
  console.log(`User ${userId} left the queue`)

  // Trigger Pusher event to notify the user they've left the queue
  if (pusherInstance) {
    pusherInstance.trigger(`user-${userId}`, "queue-left", {
      timestamp: new Date().toISOString(),
    })
  }

  return { success: true }
}

// Find a match for a user
function findMatch(userId, council, topic) {
  // This would normally query the database for potential matches
  console.log(`Finding match for user ${userId} in ${council} council`)

  // For demonstration, we'll just return a simulated match
  return null // No match found for now
}

// Create a debate when a match is found
function createDebate(user1, user2, council, topic) {
  console.log(`Creating debate between ${user1} and ${user2} in ${council} council`)

  // Generate a unique debate ID
  const debateId = `debate-${Date.now()}`

  // Notify both users about the match
  if (pusherInstance) {
    pusherInstance.trigger(`user-${user1}`, "match-found", {
      debateId,
      opponent: user2,
      council,
      topic,
    })

    pusherInstance.trigger(`user-${user2}`, "match-found", {
      debateId,
      opponent: user1,
      council,
      topic,
    })
  }

  return { debateId, success: true }
}

// Get topics for a specific council
function getTopicsForCouncil(council) {
  const topics = {
    UNSC: [
      "Nuclear Disarmament",
      "Peacekeeping Operations",
      "Terrorism and International Security",
      "Conflict Resolution in Disputed Territories",
    ],
    UNHRC: [
      "Refugee Crisis Management",
      "Human Rights Violations",
      "Freedom of Expression",
      "Rights of Indigenous Peoples",
    ],
    UNEP: ["Climate Change Solutions", "Sustainable Development", "Ocean Conservation", "Renewable Energy Transition"],
    WHO: [
      "Global Health Crisis Response",
      "Vaccine Distribution Equity",
      "Mental Health Awareness",
      "Healthcare Systems Strengthening",
    ],
    ECOSOC: [
      "Sustainable Development Goals",
      "Economic Inequality",
      "Digital Divide",
      "International Trade Regulations",
    ],
  }

  return topics[council] || []
}

// Export the module functions
module.exports = {
  init,
  joinQueue,
  leaveQueue,
  findMatch,
  createDebate,
  getTopicsForCouncil,
}
