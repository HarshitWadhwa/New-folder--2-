# CyberShield: Password Strength Analyzer & Cryptography Lab

A modern, production-grade cybersecurity tool designed to evaluate password security, calculate real-time cryptographic entropy, detect vulnerable patterns and dictionary breaches, generate high-entropy alternatives, and enforce an enterprise password reuse policy using a salted SQLite database.

---

## 🌟 Key Features

### 1. Advanced Password Strength Analysis
- **Length & Complexity**: Checks minimum length (8+), optimal length (14-16+), and character distribution across lowercase, uppercase, numbers, and special symbols.
- **Search Space & Shannon Entropy**:
  - Combinatorial Entropy: $E = L \times \log_2(R)$ (where $L$ is length and $R$ is character pool size).
  - Shannon Information Entropy: $H = -\sum p_i \log_2(p_i)$ measuring character distribution randomness.
- **Vulnerability & Pattern Detection**:
  - **Dictionary / Breach Check**: Matches against known breached and common passwords.
  - **Keyboard Walks**: Identifies horizontal and reverse patterns (e.g. `qwerty`, `asdfgh`, `123456`, `!@#$%`).
  - **Sequential Runs**: Detects sequential letters and numbers (e.g. `abc`, `789`, `987`).
  - **Repeated Characters**: Detects repeated character triplets (e.g. `aaa`, `1111`).
  - **Leet-Speak Translation**: Unmasks disguised dictionary words (e.g. `p@ssw0rd` -> `password`).
- **Multi-Vector Crack Time Estimations**:
  - Online Throttled (10 guesses/sec)
  - Online Unthrottled (1,000 guesses/sec)
  - Offline Slow Hash (10,000 guesses/sec - PBKDF2/bcrypt)
  - Offline Fast Hash (100 Billion guesses/sec - 8x RTX 4090 GPU cluster)

### 2. Password & Passphrase Generator
- **Cryptographic Random Generator**: Uses Node.js CSPRNG (`crypto.randomInt`) with customizable length (8-64) and character set filters (upper, lower, digits, symbols, ambiguous characters filter).
- **Memorable Diceware Passphrases**: Generates high-entropy multi-word passphrases in compliance with **NIST SP 800-63B** guidelines.
- **Smart Mutation Enhancer**: Takes weak user passwords and enhances them with random symbols, numbers, and case variation.

### 3. Password History & Reuse Prevention (Database)
- **Zero Plaintext Storage**: Passwords are never stored in plaintext.
- **Cryptographic Salting**: Each password generates a unique 128-bit CSPRNG salt.
- **PBKDF2-HMAC-SHA256**: Key derivation with 100,000 iterations.
- **Constant-Time Verification**: Prevents timing attack side-channel leaks (`crypto.timingSafeEqual`).
- **Policy Enforcement**: Prevents reuse of the last 5 passwords per user account.
- **Audit Table**: Visualizes stored salts and masked hashes for administrative verification.

### 4. Interactive Cryptography Laboratory
- Live side-by-side comparison of:
  - **Base64**: Explaining why encoding is NOT encryption or hashing (reversible).
  - **MD5**: Demonstrating collision vulnerability and speed risks.
  - **SHA-256 (Unsalted)**: Demonstrating vulnerability to Rainbow Tables.
  - **SHA-256 (Salted)**: Demonstrating how salt prevents precomputed tables.
  - **PBKDF2-HMAC-SHA256**: Demonstrating why work factors neutralize GPU botnets.

---

## 🚀 Quick Start

### Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher recommended; v26 tested)
- npm

### Installation
```bash
npm install
```

### Running the Web Application
```bash
npm start
```
Open your browser and navigate to: **`http://localhost:3000`**

### Running the Terminal CLI
```bash
# Interactive Menu Mode
npm run cli

# Direct Command-Line Analysis
node cli.js --analyze "YourPasswordHere"
```

### Running Automated Tests
```bash
npm test
```

---

## 📁 Project Structure

```
├── cli.js                  # Interactive terminal interface
├── package.json            # Scripts, dependencies, and metadata
├── passwords.db            # SQLite database storing salted hashes
├── public/                 # Web interface assets
│   ├── app.js              # Frontend client application logic
│   ├── index.html          # Responsive glassmorphic dark-theme UI
│   └── style.css           # Modern cyber-themed styles & animations
├── src/
│   ├── analyzer.js         # Strength, entropy & crack-time engine
│   ├── common-passwords.js # Dictionary & compromised passwords set
│   ├── database.js         # SQLite schema, salted PBKDF2 & reuse checks
│   ├── generator.js        # CSPRNG password & Diceware generator
│   └── server.js           # Express REST API
└── test/
    └── analyzer.test.js    # Node.js automated test suite
```

---

## 🛡️ Security & Cryptography Concepts Learned

1. **Entropy vs. Length**: Why length is exponentially more effective than complex character requirements ($2^{L \times \log_2(R)}$).
2. **Rainbow Tables**: How attackers pre-calculate billions of unsalted hashes into reverse lookup tables.
3. **Cryptographic Salt**: Why appending 128 bits of random data per password invalidates all pre-computed tables.
4. **Work Factor / Key Stretching**: Why modern password hashing algorithms must deliberately require high CPU/memory to resist massive GPU parallel cracking.
5. **NIST SP 800-63B Recommendations**: Why passphrases like `correct-horse-battery-staple` offer both superior security and memorability compared to short, convoluted strings with forced periodic resets.
