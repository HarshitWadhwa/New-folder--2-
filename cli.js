#!/usr/bin/env node
const readline = require('node:readline');
const crypto = require('node:crypto');
const { analyzePassword } = require('./src/analyzer');
const { generateRandomPassword, generatePassphrase, suggestStrongerAlternatives } = require('./src/generator');
const { saveUserPassword, getUserHistory } = require('./src/database');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function prompt(question) {
  return new Promise((resolve) => rl.question(question, resolve));
}

function printHeader() {
  console.log('\n=============================================================');
  console.log('  🛡️   CYBERSHIELD: Password Strength Analyzer & Security CLI');
  console.log('  NIST SP 800-63B Compliant & Cryptographic Security Engine');
  console.log('=============================================================');
}

function printAnalysis(analysis) {
  console.log(`\n--- [ Password Evaluation Report ] ---`);
  console.log(`Target Password  : ${analysis.password}`);
  console.log(`Strength Rating  : [${analysis.rating.toUpperCase()}]`);
  console.log(`Security Score   : ${analysis.score}%`);
  console.log(`Length           : ${analysis.length} characters`);
  console.log(`Character Pool   : ${analysis.charPoolSize} symbols`);
  console.log(`Search Entropy   : ${analysis.entropyBits} bits`);
  console.log(`Shannon Entropy  : ${analysis.shannonBits} bits`);

  console.log(`\n--- [ Estimated Brute-Force Crack Times ] ---`);
  console.log(`1. Online Throttled (10 guesses/sec)   : ${analysis.crackTimes.onlineThrottled}`);
  console.log(`2. Online Unthrottled (1,000/sec)      : ${analysis.crackTimes.onlineUnthrottled}`);
  console.log(`3. Offline Slow Hash (10,000/sec)      : ${analysis.crackTimes.offlineSlowHash}`);
  console.log(`4. Offline GPU Fast Hash (100B/sec)    : ${analysis.crackTimes.offlineFastHash}`);

  console.log(`\n--- [ Requirements Checklist ] ---`);
  const c = analysis.checks;
  console.log(`[${c.hasMinLength ? '✔' : '✖'}] Minimum 8 Characters`);
  console.log(`[${c.hasOptimalLength ? '✔' : '✖'}] Optimal 14+ Characters`);
  console.log(`[${c.hasLowercase ? '✔' : '✖'}] Lowercase Letters (a-z)`);
  console.log(`[${c.hasUppercase ? '✔' : '✖'}] Uppercase Letters (A-Z)`);
  console.log(`[${c.hasNumbers ? '✔' : '✖'}] Numbers (0-9)`);
  console.log(`[${c.hasSymbols ? '✔' : '✖'}] Special Symbols (!@#$...)`);
  console.log(`[${c.noRepeats ? '✔' : '✖'}] No Consecutive Repetitions`);
  console.log(`[${c.noSequences ? '✔' : '✖'}] No Sequential Patterns`);
  console.log(`[${c.noKeyboardWalks ? '✔' : '✖'}] No Keyboard Walks (e.g. qwerty)`);
  console.log(`[${c.noDictionaryMatch ? '✔' : '✖'}] Not In Breach Dictionary`);

  if (analysis.vulnerabilities.length > 0) {
    console.log(`\n⚠️  Vulnerabilities:`);
    analysis.vulnerabilities.forEach(v => console.log(`   - ${v}`));
  }

  if (analysis.recommendations.length > 0) {
    console.log(`\n💡 Recommendations:`);
    analysis.recommendations.forEach(r => console.log(`   - ${r}`));
  }
}

async function handleAnalyze() {
  const password = await prompt('\nEnter password to analyze: ');
  const analysis = analyzePassword(password);
  printAnalysis(analysis);

  const suggestions = suggestStrongerAlternatives(password);
  console.log(`\n--- [ Suggested Stronger Alternatives ] ---`);
  suggestions.forEach((s, idx) => {
    console.log(`${idx + 1}. [${s.label}]`);
    console.log(`   Password: ${s.password}`);
    console.log(`   Note    : ${s.description}\n`);
  });
}

async function handleGenerateRandom() {
  const lenStr = await prompt('\nEnter desired length (default 18): ');
  const length = parseInt(lenStr, 10) || 18;
  const pwd = generateRandomPassword({ length });
  console.log(`\nGenerated CSPRNG Random Password: ${pwd}`);
  const analysis = analyzePassword(pwd);
  console.log(`Score: ${analysis.score}% | Rating: ${analysis.rating} | Entropy: ${analysis.entropyBits} bits`);
}

async function handleGeneratePassphrase() {
  const wordsStr = await prompt('\nEnter number of words (3-6, default 4): ');
  const wordCount = parseInt(wordsStr, 10) || 4;
  const phrase = generatePassphrase({ wordCount, separator: '-' });
  console.log(`\nGenerated Memorable Diceware Passphrase: ${phrase}`);
  const analysis = analyzePassword(phrase);
  console.log(`Score: ${analysis.score}% | Rating: ${analysis.rating} | Entropy: ${analysis.entropyBits} bits`);
}

async function handleDatabaseReuse() {
  const username = await prompt('\nEnter username (e.g. alice): ');
  if (!username.trim()) {
    console.log('Username cannot be empty.');
    return;
  }

  const password = await prompt('Enter password to set for user: ');
  const result = saveUserPassword(username, password);

  if (result.success) {
    console.log(`\n✔ SUCCESS: ${result.message}`);
    console.log(`   Algorithm : ${result.details.algorithm}`);
    console.log(`   Salt      : ${result.details.saltPreview}`);
    console.log(`   Hash      : ${result.details.hashPreview}`);
  } else {
    console.log(`\n✖ DENIED: ${result.message}`);
  }

  const history = getUserHistory(username);
  console.log(`\nRecent Password History Audit Log for "${username}":`);
  if (history.length === 0) {
    console.log('  (No history)');
  } else {
    history.forEach((h, i) => {
      console.log(`  ${i + 1}. [${h.created_at}] Salt: ${h.masked_salt} | Hash: ${h.masked_hash}`);
    });
  }
}

async function handleCryptoDemo() {
  const text = await prompt('\nEnter a string to hash (default: "password123"): ') || 'password123';

  const md5 = crypto.createHash('md5').update(text).digest('hex');
  const sha256 = crypto.createHash('sha256').update(text).digest('hex');
  const salt = 'a1b2c3d4e5f67890';
  const saltedSha256 = crypto.createHash('sha256').update(salt + text).digest('hex');
  const pbkdf2 = crypto.pbkdf2Sync(text, Buffer.from(salt, 'hex'), 100000, 32, 'sha256').toString('hex');
  const b64 = Buffer.from(text).toString('base64');

  console.log(`\n--- [ Cryptography Demonstration for: "${text}" ] ---`);
  console.log(`Base64 (Encoding)    : ${b64}  <-- Reversible! NOT a hash.`);
  console.log(`MD5 (Unsalted)       : ${md5}  <-- Broken, obsolete, vulnerable to collisions.`);
  console.log(`SHA-256 (Unsalted)   : ${sha256}  <-- Fast hash; vulnerable to Rainbow Tables.`);
  console.log(`SHA-256 (Salted)     : ${saltedSha256}  <-- Salt stops Rainbow Tables, but GPUs do billions/sec.`);
  console.log(`PBKDF2 (100k iters)  : ${pbkdf2}  <-- Slow work factor halts GPU brute-force!`);
}

async function main() {
  // Check CLI arguments for direct analysis: `node cli.js --analyze "mypassword"`
  const args = process.argv.slice(2);
  if (args.length >= 2 && (args[0] === '--analyze' || args[0] === '-a')) {
    const analysis = analyzePassword(args[1]);
    printAnalysis(analysis);
    process.exit(0);
  }

  printHeader();

  while (true) {
    console.log('\nMenu Options:');
    console.log('1. Evaluate Password Strength');
    console.log('2. Generate Cryptographically Random Password');
    console.log('3. Generate Memorable Diceware Passphrase');
    console.log('4. Test Database Password Reuse Policy (SQLite + Salted PBKDF2)');
    console.log('5. Interactive Cryptography & Hashing Demonstration');
    console.log('6. Exit');

    const choice = await prompt('\nSelect an option (1-6): ');

    switch (choice.trim()) {
      case '1':
        await handleAnalyze();
        break;
      case '2':
        await handleGenerateRandom();
        break;
      case '3':
        await handleGeneratePassphrase();
        break;
      case '4':
        await handleDatabaseReuse();
        break;
      case '5':
        await handleCryptoDemo();
        break;
      case '6':
        console.log('\nExiting CyberShield. Stay secure!\n');
        rl.close();
        process.exit(0);
      default:
        console.log('Invalid option. Please enter 1-6.');
    }
  }
}

main();
