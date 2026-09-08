const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');

const DB_PATH = path.join(__dirname, '..', 'passwords.db');
const HISTORY_LIMIT = 5; // Enforce checking against last 5 passwords
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = 'sha256';

// Initialize SQLite database
const db = new DatabaseSync(DB_PATH);

// Create schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    salt_hex TEXT NOT NULL,
    iterations INTEGER NOT NULL,
    algorithm TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

/**
 * Derives a PBKDF2-HMAC-SHA256 hash using the provided salt
 */
function hashPassword(password, saltHex, iterations = PBKDF2_ITERATIONS) {
  const salt = Buffer.from(saltHex, 'hex');
  const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, PBKDF2_KEYLEN, PBKDF2_DIGEST);
  return derivedKey.toString('hex');
}

/**
 * Constant-time hash verification to prevent timing attack vulnerabilities
 */
function verifyHash(candidatePassword, storedHashHex, saltHex, iterations = PBKDF2_ITERATIONS) {
  const candidateHashHex = hashPassword(candidatePassword, saltHex, iterations);
  const bufA = Buffer.from(candidateHashHex, 'hex');
  const bufB = Buffer.from(storedHashHex, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Get or create user record
 */
function getOrCreateUser(username) {
  const cleanUser = username.trim().toLowerCase();
  const selectStmt = db.prepare('SELECT id, username, created_at FROM users WHERE username = ?');
  let user = selectStmt.get(cleanUser);

  if (!user) {
    const insertStmt = db.prepare('INSERT INTO users (username) VALUES (?)');
    insertStmt.run(cleanUser);
    user = selectStmt.get(cleanUser);
  }

  return user;
}

/**
 * Checks if the password was previously used in the last N entries and saves it if valid
 */
function saveUserPassword(username, newPassword) {
  if (!username || !username.trim()) {
    return { success: false, error: 'Username is required.' };
  }
  if (!newPassword || newPassword.length === 0) {
    return { success: false, error: 'Password cannot be empty.' };
  }

  const user = getOrCreateUser(username);

  // Fetch the last HISTORY_LIMIT passwords for this user
  const historyStmt = db.prepare(`
    SELECT id, password_hash, salt_hex, iterations, algorithm, created_at
    FROM password_history
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT ?
  `);
  const history = historyStmt.all(user.id, HISTORY_LIMIT);

  // Check against previous passwords
  for (let i = 0; i < history.length; i++) {
    const entry = history[i];
    const isReused = verifyHash(newPassword, entry.password_hash, entry.salt_hex, entry.iterations);
    if (isReused) {
      return {
        success: false,
        reused: true,
        message: `Security Alert: Password matches an entry from your previous ${history.length} passwords (used on ${entry.created_at}). Password reuse is prohibited to prevent credential cycling attacks.`,
        reusedAt: entry.created_at
      };
    }
  }

  // Generate cryptographically secure random 128-bit salt
  const saltHex = crypto.randomBytes(16).toString('hex');
  const passwordHashHex = hashPassword(newPassword, saltHex, PBKDF2_ITERATIONS);

  // Store into history
  const insertHistoryStmt = db.prepare(`
    INSERT INTO password_history (user_id, password_hash, salt_hex, iterations, algorithm)
    VALUES (?, ?, ?, ?, ?)
  `);
  insertHistoryStmt.run(user.id, passwordHashHex, saltHex, PBKDF2_ITERATIONS, `PBKDF2-HMAC-${PBKDF2_DIGEST.toUpperCase()}`);

  return {
    success: true,
    reused: false,
    message: 'Password securely hashed with unique 128-bit salt and saved to history.',
    details: {
      username: user.username,
      algorithm: `PBKDF2-HMAC-${PBKDF2_DIGEST.toUpperCase()}`,
      iterations: PBKDF2_ITERATIONS,
      saltPreview: `${saltHex.substring(0, 8)}...${saltHex.substring(saltHex.length - 8)}`,
      hashPreview: `${passwordHashHex.substring(0, 10)}...${passwordHashHex.substring(passwordHashHex.length - 10)}`
    }
  };
}

/**
 * Retrieves the non-sensitive history log for user audit display
 */
function getUserHistory(username) {
  if (!username || !username.trim()) return [];
  const cleanUser = username.trim().toLowerCase();

  const userStmt = db.prepare('SELECT id FROM users WHERE username = ?');
  const user = userStmt.get(cleanUser);
  if (!user) return [];

  const historyStmt = db.prepare(`
    SELECT id, salt_hex, iterations, algorithm, created_at,
           substr(password_hash, 1, 10) || '...' || substr(password_hash, -8) as masked_hash,
           substr(salt_hex, 1, 8) || '...' as masked_salt
    FROM password_history
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 10
  `);

  return historyStmt.all(user.id);
}

module.exports = {
  db,
  hashPassword,
  verifyHash,
  saveUserPassword,
  getUserHistory
};
