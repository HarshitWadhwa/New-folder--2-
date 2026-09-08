const { describe, it } = require('node:test');
const assert = require('node:assert');
const { analyzePassword, calculateShannonEntropy, formatCrackTime } = require('../src/analyzer');
const { generateRandomPassword, generatePassphrase, suggestStrongerAlternatives } = require('../src/generator');
const { saveUserPassword, getUserHistory, verifyHash } = require('../src/database');

describe('Password Strength Analyzer Engine', () => {
  it('should flag critically weak dictionary passwords', () => {
    const result = analyzePassword('password');
    assert.strictEqual(result.rating, 'Very Weak');
    assert.ok(result.score <= 25, `Expected score <= 25, got ${result.score}`);
    assert.strictEqual(result.checks.noDictionaryMatch, false);
    assert.strictEqual(result.checks.hasNumbers, false);
    assert.strictEqual(result.checks.hasSymbols, false);
  });

  it('should detect keyboard walk patterns like qwertyuiop', () => {
    const result = analyzePassword('qwerty123');
    assert.strictEqual(result.checks.noKeyboardWalks, false);
    assert.strictEqual(result.checks.noSequences, false);
  });

  it('should detect character repetition like aaaaaa', () => {
    const result = analyzePassword('aaaaaa12!');
    assert.strictEqual(result.checks.noRepeats, false);
  });

  it('should evaluate strong high-entropy passwords correctly', () => {
    const strongPass = 'K7#mX9$vLp2!qZ8w';
    const result = analyzePassword(strongPass);
    assert.ok(result.score >= 80, `Expected score >= 80, got ${result.score}`);
    assert.strictEqual(result.ratingClass, 'very-strong');
    assert.strictEqual(result.checks.hasMinLength, true);
    assert.strictEqual(result.checks.hasUppercase, true);
    assert.strictEqual(result.checks.hasLowercase, true);
    assert.strictEqual(result.checks.hasNumbers, true);
    assert.strictEqual(result.checks.hasSymbols, true);
    assert.ok(result.entropyBits > 65);
  });

  it('should correctly calculate Shannon entropy', () => {
    const entropyLow = calculateShannonEntropy('aaaa');
    const entropyHigh = calculateShannonEntropy('abcd');
    assert.strictEqual(entropyLow, 0);
    assert.ok(entropyHigh > entropyLow);
  });
});

describe('Password & Passphrase Generator', () => {
  it('should generate cryptographically random passwords matching length and constraints', () => {
    const pwd = generateRandomPassword({ length: 20, includeUpper: true, includeLower: true, includeNumbers: true, includeSymbols: true });
    assert.strictEqual(pwd.length, 20);
    assert.match(pwd, /[a-z]/);
    assert.match(pwd, /[A-Z]/);
    assert.match(pwd, /[0-9]/);
    assert.match(pwd, /[^a-zA-Z0-9]/);
  });

  it('should generate multi-word Diceware passphrases', () => {
    const passphrase = generatePassphrase({ wordCount: 4, separator: '-' });
    const parts = passphrase.split('-');
    assert.ok(parts.length >= 4, `Expected at least 4 segments, got ${parts.length}`);
  });

  it('should provide smart alternatives for a given user password', () => {
    const suggestions = suggestStrongerAlternatives('weakpass');
    assert.ok(suggestions.length >= 3);
    assert.ok(suggestions.some(s => s.type === 'passphrase'));
    assert.ok(suggestions.some(s => s.type === 'enhanced_base'));
  });
});

describe('Database & Password Reuse Prevention Policy', () => {
  const testUser = `testuser_${Date.now()}`;

  it('should allow saving an initial secure password with salted PBKDF2 hash', () => {
    const res = saveUserPassword(testUser, 'InitialSecurePass!123');
    assert.strictEqual(res.success, true);
    assert.strictEqual(res.reused, false);
    assert.ok(res.details.saltPreview);
  });

  it('should reject immediate reuse of the same password', () => {
    const res = saveUserPassword(testUser, 'InitialSecurePass!123');
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.reused, true);
    assert.match(res.message, /Password matches an entry from your previous/);
  });

  it('should allow a distinct new password and track history', () => {
    const res = saveUserPassword(testUser, 'SecondDifferentPass!456');
    assert.strictEqual(res.success, true);

    const history = getUserHistory(testUser);
    assert.strictEqual(history.length, 2);
    assert.ok(history[0].masked_hash);
    assert.ok(history[0].masked_salt);
  });
});
