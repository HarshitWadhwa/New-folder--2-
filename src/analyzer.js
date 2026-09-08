const { commonPasswords } = require('./common-passwords');

// Keyboard walk patterns
const KEYBOARD_ROWS = [
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
  '1234567890',
  '!@#$%^&*()'
];

// Leetspeak character substitutions map
const LEET_MAP = {
  '@': 'a', '4': 'a',
  '8': 'b',
  '(': 'c',
  '3': 'e',
  '9': 'g',
  '1': 'i', '!': 'i', '|': 'i',
  '0': 'o',
  '5': 's', '$': 's',
  '7': 't', '+': 't',
  '2': 'z'
};

function normalizeLeetspeak(str) {
  let res = '';
  for (const char of str.toLowerCase()) {
    res += LEET_MAP[char] || char;
  }
  return res;
}

function detectRepeats(password) {
  // Checks for 3 or more repeated characters consecutively (e.g. "aaa", "111")
  const repeatRegex = /(.)\1{2,}/i;
  return repeatRegex.test(password);
}

function detectSequences(password) {
  const lower = password.toLowerCase();
  for (let i = 0; i <= lower.length - 3; i++) {
    const c1 = lower.charCodeAt(i);
    const c2 = lower.charCodeAt(i + 1);
    const c3 = lower.charCodeAt(i + 2);

    // Forward sequence (e.g., abc, 123)
    if (c2 === c1 + 1 && c3 === c2 + 1) {
      // Check if they are alphanumeric
      if ((c1 >= 48 && c3 <= 57) || (c1 >= 97 && c3 <= 122)) {
        return true;
      }
    }
    // Backward sequence (e.g., cba, 321)
    if (c2 === c1 - 1 && c3 === c2 - 1) {
      if ((c3 >= 48 && c1 <= 57) || (c3 >= 97 && c1 <= 122)) {
        return true;
      }
    }
  }
  return false;
}

function detectKeyboardWalks(password) {
  const lower = password.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    const revRow = row.split('').reverse().join('');
    for (let len = 3; len <= row.length; len++) {
      for (let i = 0; i <= row.length - len; i++) {
        const sub = row.substring(i, i + len);
        const revSub = revRow.substring(i, i + len);
        if (lower.includes(sub) || lower.includes(revSub)) {
          return true;
        }
      }
    }
  }
  return false;
}

function detectDictionaryMatch(password) {
  const lower = password.toLowerCase();
  const leetNormalized = normalizeLeetspeak(lower);

  // Exact match
  if (commonPasswords.has(lower) || commonPasswords.has(leetNormalized)) {
    return { isMatch: true, type: 'exact' };
  }

  // Substring match for longer passwords
  for (const common of commonPasswords) {
    if (common.length >= 4 && (lower.includes(common) || leetNormalized.includes(common))) {
      return { isMatch: true, type: 'substring', matchedWord: common };
    }
  }

  return { isMatch: false };
}

function calculateShannonEntropy(password) {
  if (!password) return 0;
  const len = password.length;
  const freq = {};
  for (const char of password) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  // Total Shannon entropy in bits
  return Number((entropy * len).toFixed(2));
}

function formatCrackTime(seconds) {
  if (seconds < 1) return 'Instantly';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)} minutes`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)} hours`;
  const days = hours / 24;
  if (days < 30) return `${Math.round(days)} days`;
  const months = days / 30.44;
  if (months < 12) return `${Math.round(months)} months`;
  const years = days / 365.25;
  if (years < 100) return `${Math.round(years)} years`;
  if (years < 1000) return `${Math.round(years / 100) * 100} years`;
  if (years < 1000000) return `${(years / 1000).toFixed(1)}k years`;
  if (years < 1000000000) return `${(years / 1000000).toFixed(1)}M years`;
  if (years < 1000000000000) return `${(years / 1000000000).toFixed(1)}B years`;
  return 'Trillions of years (Effectively Uncrackable)';
}

function analyzePassword(password) {
  if (typeof password !== 'string' || password.length === 0) {
    return {
      password: '',
      score: 0,
      rating: 'Empty',
      ratingClass: 'empty',
      length: 0,
      charPoolSize: 0,
      entropyBits: 0,
      shannonBits: 0,
      estimatedGuesses: '0',
      crackTimes: {
        onlineThrottled: 'Instantly',
        onlineUnthrottled: 'Instantly',
        offlineSlowHash: 'Instantly',
        offlineFastHash: 'Instantly'
      },
      checks: {
        hasMinLength: false,
        hasOptimalLength: false,
        hasLowercase: false,
        hasUppercase: false,
        hasNumbers: false,
        hasSymbols: false,
        noRepeats: true,
        noSequences: true,
        noKeyboardWalks: true,
        noDictionaryMatch: true
      },
      strengths: [],
      vulnerabilities: ['Please enter a password to evaluate.'],
      recommendations: ['Use at least 12-16 characters with a combination of letters, numbers, and symbols, or a 4-word passphrase.']
    };
  }

  const length = password.length;
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSymbols = /[^a-zA-Z0-9]/.test(password);

  // Calculate Character Pool Size (R)
  let poolSize = 0;
  if (hasLowercase) poolSize += 26;
  if (hasUppercase) poolSize += 26;
  if (hasNumbers) poolSize += 10;
  if (hasSymbols) poolSize += 33;

  // Search space entropy: E = L * log2(R)
  const poolEntropyBits = poolSize > 0 ? Number((length * Math.log2(poolSize)).toFixed(1)) : 0;
  const shannonBits = calculateShannonEntropy(password);

  // Pattern detections
  const hasRepeats = detectRepeats(password);
  const hasSequences = detectSequences(password);
  const hasKeyboardWalks = detectKeyboardWalks(password);
  const dictResult = detectDictionaryMatch(password);

  // Strengths and Vulnerabilities lists
  const strengths = [];
  const vulnerabilities = [];
  const recommendations = [];

  // Length check
  const hasMinLength = length >= 8;
  const hasOptimalLength = length >= 14;

  if (length < 8) {
    vulnerabilities.push(`Critically short (${length} chars). NIST recommends at least 8-12+ characters.`);
    recommendations.push('Increase length to at least 12 to 16 characters.');
  } else if (length < 12) {
    strengths.push(`Acceptable length (${length} chars), though longer is safer.`);
    recommendations.push('Add 4 or more characters to dramatically increase brute-force resistance.');
  } else if (length >= 16) {
    strengths.push(`Outstanding length (${length} chars) providing exponential brute-force protection.`);
  } else {
    strengths.push(`Good length (${length} chars).`);
  }

  // Complexity types
  const complexityCount = [hasLowercase, hasUppercase, hasNumbers, hasSymbols].filter(Boolean).length;
  if (complexityCount === 4) {
    strengths.push('Complete character variety: includes lowercase, uppercase, numbers, and symbols.');
  } else {
    const missing = [];
    if (!hasLowercase) missing.push('lowercase letters');
    if (!hasUppercase) missing.push('uppercase letters');
    if (!hasNumbers) missing.push('numbers');
    if (!hasSymbols) missing.push('special symbols');
    vulnerabilities.push(`Lacks character diversity: missing ${missing.join(', ')}.`);
    recommendations.push(`Include ${missing.join(' and ')} to expand the search pool.`);
  }

  // Patterns
  if (hasRepeats) {
    vulnerabilities.push('Contains 3+ consecutively repeated characters (e.g. "aaa", "111").');
    recommendations.push('Avoid repeating identical characters consecutively.');
  }
  if (hasSequences) {
    vulnerabilities.push('Contains predictable alphabetical or numeric sequences (e.g. "abc", "123").');
    recommendations.push('Avoid sequential runs of characters.');
  }
  if (hasKeyboardWalks) {
    vulnerabilities.push('Contains keyboard walk patterns (e.g. "qwerty", "asdf").');
    recommendations.push('Avoid common keyboard row patterns which attackers test first.');
  }
  if (dictResult.isMatch) {
    if (dictResult.type === 'exact') {
      vulnerabilities.push('Found directly in common password breach databases! Easily compromised in seconds.');
    } else {
      vulnerabilities.push(`Contains common dictionary word "${dictResult.matchedWord}", exposing it to dictionary attacks.`);
    }
    recommendations.push('Replace dictionary words with random characters or use an unpredictable passphrase.');
  }

  // Calculate Base Score (0 to 100)
  let score = 0;

  // Length scoring (up to 45 pts)
  if (length >= 16) score += 45;
  else if (length >= 12) score += 35 + (length - 12) * 2.5;
  else if (length >= 8) score += 20 + (length - 8) * 3.75;
  else score += length * 2.5;

  // Complexity scoring (up to 35 pts)
  if (complexityCount === 4) score += 35;
  else if (complexityCount === 3) score += 25;
  else if (complexityCount === 2) score += 15;
  else score += 5;

  // Entropy bonus (up to 20 pts)
  if (poolEntropyBits >= 80) score += 20;
  else if (poolEntropyBits >= 60) score += 15;
  else if (poolEntropyBits >= 40) score += 10;
  else if (poolEntropyBits >= 25) score += 5;

  // Penalties
  if (dictResult.isMatch) {
    score = dictResult.type === 'exact' ? Math.min(score, 15) : score - 25;
  }
  if (hasRepeats) score -= 12;
  if (hasSequences) score -= 12;
  if (hasKeyboardWalks) score -= 15;
  if (length < 8) score = Math.min(score, 30);

  // Clamp score
  score = Math.max(5, Math.min(100, Math.round(score)));

  // Rating label
  let rating = 'Very Weak';
  let ratingClass = 'very-weak';
  if (score >= 85) {
    rating = 'Very Strong';
    ratingClass = 'very-strong';
  } else if (score >= 70) {
    rating = 'Strong';
    ratingClass = 'strong';
  } else if (score >= 50) {
    rating = 'Moderate';
    ratingClass = 'moderate';
  } else if (score >= 30) {
    rating = 'Weak';
    ratingClass = 'weak';
  }

  // Crack Time Estimation
  // Effective entropy: penalize if patterns exist for realistic crack estimate
  let effectiveEntropy = poolEntropyBits;
  if (dictResult.isMatch) effectiveEntropy = Math.min(effectiveEntropy, 15);
  if (hasKeyboardWalks) effectiveEntropy -= 10;
  if (hasSequences) effectiveEntropy -= 8;
  if (hasRepeats) effectiveEntropy -= 6;
  effectiveEntropy = Math.max(8, effectiveEntropy);

  const combinations = Math.pow(2, effectiveEntropy);
  const avgGuesses = combinations / 2;

  // Attack speeds:
  // 1. Online throttled: 10 guesses / sec (defense against remote brute force)
  // 2. Online unthrottled: 1,000 guesses / sec (fast unmetered HTTP endpoints)
  // 3. Offline slow hash: 10,000 guesses / sec (bcrypt cost 12, Argon2id, PBKDF2 100k)
  // 4. Offline fast hash: 100,000,000,000 (100 Billion) guesses / sec (GPU cluster against MD5 / NTLM / SHA1)

  const crackTimes = {
    onlineThrottled: formatCrackTime(avgGuesses / 10),
    onlineUnthrottled: formatCrackTime(avgGuesses / 1000),
    offlineSlowHash: formatCrackTime(avgGuesses / 10000),
    offlineFastHash: formatCrackTime(avgGuesses / 100000000000)
  };

  return {
    password,
    score,
    rating,
    ratingClass,
    length,
    charPoolSize: poolSize,
    entropyBits: poolEntropyBits,
    shannonBits,
    effectiveEntropy: Number(effectiveEntropy.toFixed(1)),
    crackTimes,
    checks: {
      hasMinLength,
      hasOptimalLength,
      hasLowercase,
      hasUppercase,
      hasNumbers,
      hasSymbols,
      noRepeats: !hasRepeats,
      noSequences: !hasSequences,
      noKeyboardWalks: !hasKeyboardWalks,
      noDictionaryMatch: !dictResult.isMatch
    },
    strengths,
    vulnerabilities,
    recommendations: recommendations.length ? recommendations : ['Great password! Complies with high-security guidelines.']
  };
}

module.exports = {
  analyzePassword,
  calculateShannonEntropy,
  formatCrackTime
};
