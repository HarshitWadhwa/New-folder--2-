const crypto = require('node:crypto');

// Curated Diceware word list of recognizable, memorable words
const WORD_LIST = [
  'anchor', 'apple', 'arrow', 'artist', 'badger', 'bamboo', 'beacon', 'breeze',
  'bridge', 'cactus', 'canyon', 'castle', 'cherry', 'cipher', 'clover', 'cobalt',
  'comet', 'copper', 'coral', 'crater', 'crystal', 'curiosity', 'dancer', 'dawn',
  'desert', 'dolphin', 'dragon', 'eagle', 'echo', 'ember', 'falcon', 'feather',
  'field', 'flame', 'forest', 'fossil', 'galaxy', 'garden', 'geyser', 'glacier',
  'gravity', 'harbor', 'haven', 'hawk', 'horizon', 'iceberg', 'island', 'jasper',
  'jungle', 'jupiter', 'lagoon', 'lantern', 'laser', 'legend', 'leopard', 'lightning',
  'lotus', 'lunar', 'magnet', 'mango', 'mantle', 'meadow', 'meteor', 'mirage',
  'monarch', 'mountain', 'nebula', 'nectar', 'neutron', 'ninja', 'nova', 'oasis',
  'ocean', 'olive', 'orbit', 'orchid', 'panther', 'pebble', 'phoenix', 'pioneer',
  'planet', 'plasma', 'prism', 'pulse', 'pyramid', 'quantum', 'quasar', 'radiant',
  'rainbow', 'raven', 'reef', 'river', 'rocket', 'ruby', 'safari', 'sailor',
  'saturn', 'shadow', 'shield', 'siren', 'solar', 'spark', 'sphinx', 'spirit',
  'star', 'stone', 'storm', 'stride', 'summit', 'sunrise', 'sunset', 'timber',
  'titan', 'topaz', 'torch', 'torrent', 'tower', 'tulip', 'tundra', 'turtle',
  'valley', 'vapor', 'velvet', 'vessel', 'viper', 'volcano', 'voyage', 'walnut',
  'wave', 'whisper', 'willow', 'winter', 'wolf', 'zenith', 'zephyr', 'zodiac',
  'battery', 'staple', 'horse', 'correct', 'shield', 'matrix', 'silver', 'trophy',
  'glider', 'aurora', 'cosmic', 'dynamo', 'fable', 'glimmer', 'hybrid', 'matrix'
];

const CHAR_SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?',
  ambiguous: 'Il1O0o|'
};

function getRandomChar(charString) {
  const index = crypto.randomInt(0, charString.length);
  return charString[index];
}

function shuffleArray(array) {
  // Fisher-Yates shuffle using cryptographically secure random integers
  for (let i = array.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

/**
 * Generates a cryptographically secure random password
 */
function generateRandomPassword(options = {}) {
  const {
    length = 16,
    includeUpper = true,
    includeLower = true,
    includeNumbers = true,
    includeSymbols = true,
    excludeAmbiguous = false
  } = options;

  let pool = '';
  const requiredChars = [];

  let lower = CHAR_SETS.lower;
  let upper = CHAR_SETS.upper;
  let numbers = CHAR_SETS.numbers;
  let symbols = CHAR_SETS.symbols;

  if (excludeAmbiguous) {
    const removeAmbiguous = (str) => str.split('').filter(c => !CHAR_SETS.ambiguous.includes(c)).join('');
    lower = removeAmbiguous(lower);
    upper = removeAmbiguous(upper);
    numbers = removeAmbiguous(numbers);
    symbols = removeAmbiguous(symbols);
  }

  if (includeLower && lower.length > 0) {
    pool += lower;
    requiredChars.push(getRandomChar(lower));
  }
  if (includeUpper && upper.length > 0) {
    pool += upper;
    requiredChars.push(getRandomChar(upper));
  }
  if (includeNumbers && numbers.length > 0) {
    pool += numbers;
    requiredChars.push(getRandomChar(numbers));
  }
  if (includeSymbols && symbols.length > 0) {
    pool += symbols;
    requiredChars.push(getRandomChar(symbols));
  }

  if (pool.length === 0) {
    pool = CHAR_SETS.lower + CHAR_SETS.numbers;
    requiredChars.push(getRandomChar(pool));
  }

  const passwordChars = [...requiredChars];
  const targetLength = Math.max(requiredChars.length, Math.min(64, length));

  while (passwordChars.length < targetLength) {
    passwordChars.push(getRandomChar(pool));
  }

  return shuffleArray(passwordChars).join('');
}

/**
 * Generates a memorable Diceware-style passphrase
 */
function generatePassphrase(options = {}) {
  const {
    wordCount = 4,
    separator = '-',
    capitalize = true,
    includeNumber = true,
    includeSymbol = true
  } = options;

  const count = Math.max(3, Math.min(8, wordCount));
  const selectedWords = [];

  for (let i = 0; i < count; i++) {
    const word = WORD_LIST[crypto.randomInt(0, WORD_LIST.length)];
    selectedWords.push(capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word);
  }

  let passphrase = selectedWords.join(separator);

  if (includeNumber) {
    const randomNum = crypto.randomInt(10, 999);
    passphrase += `${separator}${randomNum}`;
  }

  if (includeSymbol) {
    const safeSymbols = '!#*&$%';
    const randomSym = safeSymbols[crypto.randomInt(0, safeSymbols.length)];
    passphrase += randomSym;
  }

  return passphrase;
}

/**
 * Suggests stronger alternatives based on the user's entered password
 */
function suggestStrongerAlternatives(userPassword) {
  const suggestions = [];
  const trimmed = (userPassword || '').trim();

  // Suggestion 1: High-entropy Passphrase (NIST-recommended modern approach)
  suggestions.push({
    type: 'passphrase',
    label: 'Memorable Passphrase (NIST SP 800-63B Style)',
    description: 'Easy to remember, exceptionally hard for computers to brute-force.',
    password: generatePassphrase({ wordCount: 4, separator: '-', capitalize: true, includeNumber: true })
  });

  // Suggestion 2: Ultra-Secure Random
  suggestions.push({
    type: 'random_strong',
    label: 'Cryptographically Secure Random (18 Chars)',
    description: 'Maximum entropy using CSPRNG with letters, numbers, and symbols.',
    password: generateRandomPassword({ length: 18, includeUpper: true, includeLower: true, includeNumbers: true, includeSymbols: true })
  });

  // Suggestion 3: Smart Mutation of User's Input (if user provided something)
  if (trimmed.length > 0) {
    // Transform base password:
    // 1. Capitalize first letter or alternating
    let mutated = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);

    // 2. Ensure missing types are added
    const symbols = '!@#$%^&*?';
    const randSym1 = symbols[crypto.randomInt(0, symbols.length)];
    const randSym2 = symbols[crypto.randomInt(0, symbols.length)];
    const randNum = crypto.randomInt(100, 999);

    // If password was short or dictionary-like, wrap and pad with high entropy
    mutated = `${randSym1}${mutated}_${randNum}${randSym2}`;

    suggestions.push({
      type: 'enhanced_base',
      label: 'Hardened Variant of Your Password',
      description: 'Keeps your core idea but injects high-entropy bounds, symbols, and numbers.',
      password: mutated
    });
  } else {
    // Alternative 12-char compact random
    suggestions.push({
      type: 'compact_secure',
      label: 'Balanced Secure Password (14 Chars)',
      description: 'Balanced length and complexity for standard website requirements.',
      password: generateRandomPassword({ length: 14, includeUpper: true, includeLower: true, includeNumbers: true, includeSymbols: true })
    });
  }

  return suggestions;
}

module.exports = {
  generateRandomPassword,
  generatePassphrase,
  suggestStrongerAlternatives
};
