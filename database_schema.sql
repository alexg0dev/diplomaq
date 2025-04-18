-- Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(50) UNIQUE,
    avatar_url TEXT,
    subscription VARCHAR(20) DEFAULT 'free',
    subscription_expiry TIMESTAMP,
    subscription_updated TIMESTAMP,
    kofi_transaction_id VARCHAR(255),
    loyalty_points INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    debates_joined INTEGER DEFAULT 0,
    debates_created INTEGER DEFAULT 0,
    debates_joined_today INTEGER DEFAULT 0,
    last_debate_join_date TIMESTAMP
);

-- Debates Table
CREATE TABLE debates (
    id UUID PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    council VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP
);

-- Debate Participants Table
CREATE TABLE debate_participants (
    id SERIAL PRIMARY KEY,
    debate_id UUID REFERENCES debates(id),
    user_id UUID REFERENCES users(id),
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_creator BOOLEAN DEFAULT FALSE,
    UNIQUE(debate_id, user_id)
);

-- Messages Table
CREATE TABLE messages (
    id UUID PRIMARY KEY,
    debate_id UUID REFERENCES debates(id),
    user_id UUID REFERENCES users(id),
    content TEXT NOT NULL,
    is_ai BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Payments Table
CREATE TABLE payments (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    type VARCHAR(50) NOT NULL,
    tier VARCHAR(20),
    amount DECIMAL(10, 2),
    currency VARCHAR(3),
    transaction_id VARCHAR(255),
    loyalty_points_earned INTEGER DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_debates_status ON debates(status);
CREATE INDEX idx_debates_council ON debates(council);
CREATE INDEX idx_debate_participants_debate_id ON debate_participants(debate_id);
CREATE INDEX idx_debate_participants_user_id ON debate_participants(user_id);
CREATE INDEX idx_messages_debate_id ON messages(debate_id);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);
CREATE INDEX idx_payments_user_id ON payments(user_id);

-- Functions and triggers for debate limits
CREATE OR REPLACE FUNCTION reset_daily_debate_count()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if it's a new day since last join
    IF NEW.last_debate_join_date IS NULL OR 
       DATE(NEW.last_debate_join_date) < DATE(CURRENT_TIMESTAMP) THEN
        NEW.debates_joined_today := 1;
    ELSE
        NEW.debates_joined_today := NEW.debates_joined_today + 1;
    END IF;
    
    NEW.last_debate_join_date := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_reset_daily_debate_count
BEFORE UPDATE ON users
FOR EACH ROW
WHEN (NEW.debates_joined_today <> OLD.debates_joined_today)
EXECUTE FUNCTION reset_daily_debate_count();

-- Function to check if user can join more debates
CREATE OR REPLACE FUNCTION can_join_more_debates(user_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    user_record RECORD;
    daily_limit INTEGER;
BEGIN
    -- Get user record
    SELECT * INTO user_record FROM users WHERE id = user_id;
    
    -- Reset count if it's a new day
    IF user_record.last_debate_join_date IS NULL OR 
       DATE(user_record.last_debate_join_date) < DATE(CURRENT_TIMESTAMP) THEN
        UPDATE users SET debates_joined_today = 0 WHERE id = user_id;
        SELECT * INTO user_record FROM users WHERE id = user_id;
    END IF;
    
    -- Set daily limit based on subscription
    CASE user_record.subscription
        WHEN 'pro' THEN daily_limit := 20;
        WHEN 'elite' THEN daily_limit := 50;
        WHEN 'institutional' THEN daily_limit := 100;
        ELSE daily_limit := 8; -- free tier
    END CASE;
    
    -- Check if user can join more debates
    RETURN user_record.debates_joined_today < daily_limit;
END;
$$ LANGUAGE plpgsql;
