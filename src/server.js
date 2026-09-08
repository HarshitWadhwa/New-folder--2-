const express = require('express');
const cors = require('cors');
const path = require('node:path');
const crypto = require('node:crypto');

const { analyzePassword } = require('./analyzer');
const { generateRandomPassword, generatePassphrase, suggestStrongerAlternatives } = require('./generator');
const { saveUserPassword, getUserHistory } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// API: Analyze password strength
app.post('/api/analyze', (req, res) => {
  const { password } = req.body;
  const analysis = analyzePassword(password || '');
  const suggestions = suggestStrongerAlternatives(password || '');
  res.json({
    ...analysis,
    suggestions
  });
});

// API: Generate passwords
app.post('/api/generate', (req, res) => {
  const { type = 'random', ...options } = req.body;

  if (type === 'passphrase') {
    const passphrase = generatePassphrase(options);
    const analysis = analyzePassword(passphrase);
    return res.json({ password: passphrase, analysis });
  }

  const password = generateRandomPassword(options);
  const analysis = analyzePassword(password);
  res.json({ password, analysis });
});

// API: Suggest alternatives for input
app.post('/api/suggest', (req, res) => {
  const { password = '' } = req.body;
  const suggestions = suggestStrongerAlternatives(password);
  res.json({ suggestions });
});

// API: Save password to database with reuse check
app.post('/api/save-password', (req, res) => {
  const { username, password } = req.body;

  if (!username || !username.trim()) {
    return res.status(400).json({ success: false, message: 'Username is required.' });
  }
  if (!password) {
    return res.status(400).json({ success: false, message: 'Password cannot be empty.' });
  }

  const result = saveUserPassword(username, password);
  if (!result.success && result.reused) {
    return res.status(409).json(result);
  }
  res.json(result);
});

// API: Get user history audit log
app.get('/api/history/:username', (req, res) => {
  const { username } = req.params;
  const history = getUserHistory(username);
  res.json({ username, history });
});

// API: Live Educational Cryptography Demo
app.post('/api/crypto-demo', (req, res) => {
  const { text = 'password123' } = req.body;

  // 1. MD5 (Fast, broken hash)
  const md5Hash = crypto.createHash('md5').update(text).digest('hex');

  // 2. SHA-256 (Unsalted cryptographic hash)
  const sha256Hash = crypto.createHash('sha256').update(text).digest('hex');

  // 3. Salted SHA-256
  const sampleSalt = 'a1b2c3d4e5f67890';
  const saltedSha256 = crypto.createHash('sha256').update(sampleSalt + text).digest('hex');

  // 4. PBKDF2 with 100,000 iterations (Slow key derivation)
  const pbkdf2Salt = Buffer.from(sampleSalt, 'hex');
  const pbkdf2Derived = crypto.pbkdf2Sync(text, pbkdf2Salt, 100000, 32, 'sha256').toString('hex');

  // 5. Base64 encoding (demonstrating reversible encoding vs one-way hash)
  const base64Encoded = Buffer.from(text).toString('base64');

  res.json({
    input: text,
    encoding: {
      algorithm: 'Base64',
      value: base64Encoded,
      isReversible: true,
      reversibleOutput: Buffer.from(base64Encoded, 'base64').toString('utf8'),
      note: 'Encoding is NOT encryption or hashing. It is trivial to reverse back to plaintext.'
    },
    hashes: [
      {
        algorithm: 'MD5',
        type: 'Fast Hash (Obsolete)',
        hash: md5Hash,
        salt: 'None',
        vulnerabilities: 'Extremely vulnerable to Rainbow Tables and collision attacks. Can compute > 100 billion hashes/sec on GPUs.'
      },
      {
        algorithm: 'SHA-256 (Unsalted)',
        type: 'Standard Hash (Raw)',
        hash: sha256Hash,
        salt: 'None',
        vulnerabilities: 'Identical inputs produce identical outputs everywhere. Vulnerable to precomputed Rainbow Tables.'
      },
      {
        algorithm: 'SHA-256 (Salted)',
        type: 'Salted Fast Hash',
        hash: saltedSha256,
        salt: sampleSalt,
        vulnerabilities: 'Salt eliminates Rainbow Tables, but GPUs can still brute-force billions of guesses/sec due to zero work factor.'
      },
      {
        algorithm: 'PBKDF2-HMAC-SHA256 (100k Iterations)',
        type: 'Adaptive Key Derivation (Slow Hash)',
        hash: pbkdf2Derived,
        salt: sampleSalt,
        vulnerabilities: 'High work factor forces attackers to expend significant computational time per guess, neutralising GPU botnets.'
      }
    ]
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(` 🛡️  Password Strength Analyzer & Security Lab`);
    console.log(` 🚀 Server running at: http://localhost:${PORT}`);
    console.log(` 📂 Database initialized: passwords.db`);
    console.log(`====================================================`);
  });
}

module.exports = app;
