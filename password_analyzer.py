"""
===================================================================
 PASSWORD STRENGTH ANALYZER & SECURITY LAB (Python Standard Library)
===================================================================
Features:
 1. Evaluates Password Length, Complexity, and Uniqueness
 2. Calculates Cryptographic Entropy & Estimated Crack Time
 3. Suggests Stronger Alternatives & Memorable Passphrases
 4. SQLite Database to Prevent Password Reuse (using Salted Hashes)
 5. Educational Notes on Cryptography (Salt, Hashing, Rainbow Tables)
 
Requires NO pip installations - uses only Python standard libraries:
 (re, math, secrets, hashlib, sqlite3, sys, os)
===================================================================
"""

import re
import math
import secrets
import hashlib
import sqlite3
import sys
import os

# Ensure safe UTF-8 terminal output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Top common/breached passwords for dictionary lookup
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "111111",
    "1234567", "sunshine", "qwerty", "iloveyou", "princess", "admin",
    "welcome", "666666", "football", "monkey", "charlie", "donald",
    "dragon", "baseball", "pass", "master", "shadow", "superman",
    "secret", "trustno1", "letmein", "changeme", "admin123", "root123"
}

KEYBOARD_PATTERNS = ["qwerty", "asdfgh", "zxcvbn", "123456", "qazwsx"]

# Curated word list for memorable Diceware passphrases (NIST SP 800-63B)
PASSPHRASE_WORDS = [
    "anchor", "apple", "beacon", "breeze", "cactus", "canyon", "castle",
    "crystal", "dancer", "dolphin", "dragon", "eagle", "falcon", "forest",
    "galaxy", "glacier", "gravity", "harbor", "horizon", "island", "jungle",
    "jupiter", "laser", "legend", "leopard", "lunar", "meteor", "mountain",
    "nebula", "ninja", "oasis", "ocean", "orbit", "panther", "phoenix",
    "planet", "prism", "pyramid", "quantum", "rainbow", "rocket", "shadow",
    "shield", "solar", "storm", "summit", "timber", "titan", "turtle", "winter"
]


# ===================================================================
# 1. PASSWORD EVALUATION ENGINE
# ===================================================================

def calculate_entropy(password, pool_size):
    """
    Calculates Shannon / search-space entropy in bits:
    Entropy (E) = Length * log2(Pool Size)
    """
    if not password or pool_size <= 0:
        return 0.0
    return round(len(password) * math.log2(pool_size), 2)


def estimate_crack_time(entropy_bits):
    """
    Estimates the time to crack via offline fast hash attack (100 Billion guesses/sec).
    """
    combinations = 2 ** entropy_bits
    avg_guesses = combinations / 2
    guesses_per_sec = 100_000_000_000  # Modern GPU attack speed

    seconds = avg_guesses / guesses_per_sec

    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds // 86400)} days"
    elif seconds < 31536000 * 100:
        return f"{int(seconds // 31536000)} years"
    else:
        return "Centuries (Effectively Uncrackable)"


def analyze_password(password):
    """
    Evaluates password length, complexity, uniqueness, and vulnerabilities.
    Returns a comprehensive analysis dictionary.
    """
    if not password:
        return {
            "password": "",
            "score": 0,
            "rating": "Empty",
            "checks": {},
            "vulnerabilities": ["Password cannot be empty."],
            "recommendations": ["Enter a password with at least 12 characters."]
        }

    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    # Calculate character pool size (R)
    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 33

    entropy = calculate_entropy(password, pool_size)
    crack_time = estimate_crack_time(entropy)

    # Uniqueness & Pattern checks
    lower_pass = password.lower()
    is_common = lower_pass in COMMON_PASSWORDS or any(p in lower_pass for p in COMMON_PASSWORDS if len(p) >= 5)
    has_repeats = bool(re.search(r'(.)\1{2,}', password))  # e.g. "aaa", "111"
    has_walks = any(walk in lower_pass or walk[::-1] in lower_pass for walk in KEYBOARD_PATTERNS)
    
    # Sequential pattern check (e.g. "abc", "123")
    has_sequences = False
    for i in range(len(lower_pass) - 2):
        c1, c2, c3 = ord(lower_pass[i]), ord(lower_pass[i+1]), ord(lower_pass[i+2])
        if (c2 == c1 + 1 and c3 == c2 + 1) or (c2 == c1 - 1 and c3 == c2 - 1):
            has_sequences = True
            break

    # Scoring (0 - 100)
    score = 0

    # Length points (up to 40 pts)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        score += length * 2

    # Complexity points (up to 40 pts)
    types_count = sum([has_lower, has_upper, has_digit, has_symbol])
    score += types_count * 10

    # Entropy bonus (up to 20 pts)
    if entropy >= 70:
        score += 20
    elif entropy >= 50:
        score += 15
    elif entropy >= 35:
        score += 10

    # Penalties for predictable patterns
    vulnerabilities = []
    recommendations = []

    if is_common:
        score -= 40
        vulnerabilities.append("Found in common/breached passwords list (High Risk).")
        recommendations.append("Do not use dictionary words or widely leaked passwords.")

    if has_repeats:
        score -= 10
        vulnerabilities.append("Contains 3+ repeated characters in a row (e.g. 'aaa').")
        recommendations.append("Avoid repeating the same character consecutively.")

    if has_sequences:
        score -= 10
        vulnerabilities.append("Contains sequential characters (e.g. 'abc', '123').")
        recommendations.append("Avoid ascending or descending number/letter sequences.")

    if has_walks:
        score -= 15
        vulnerabilities.append("Contains keyboard walk pattern (e.g. 'qwerty', 'asdf').")
        recommendations.append("Avoid common keyboard row combinations.")

    if length < 8:
        vulnerabilities.append(f"Too short ({length} characters). Minimum recommended is 8-12.")
        recommendations.append("Increase length to at least 12-16 characters.")

    if types_count < 3:
        vulnerabilities.append("Low character diversity.")
        recommendations.append("Mix lowercase, uppercase, numbers, and special symbols.")

    # Clamp score
    score = max(5, min(100, score))

    # Rating label
    if score >= 85:
        rating = "Very Strong"
    elif score >= 70:
        rating = "Strong"
    elif score >= 50:
        rating = "Moderate"
    elif score >= 30:
        rating = "Weak"
    else:
        rating = "Very Weak"

    return {
        "password": password,
        "score": score,
        "rating": rating,
        "length": length,
        "pool_size": pool_size,
        "entropy_bits": entropy,
        "crack_time": crack_time,
        "checks": {
            "Min 8 Characters": length >= 8,
            "Optimal 12+ Characters": length >= 12,
            "Has Lowercase (a-z)": has_lower,
            "Has Uppercase (A-Z)": has_upper,
            "Has Numbers (0-9)": has_digit,
            "Has Special Symbols": has_symbol,
            "No Repeated Characters": not has_repeats,
            "No Sequential Runs": not has_sequences,
            "No Keyboard Walks": not has_walks,
            "Not in Breach Dictionary": not is_common
        },
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations if recommendations else ["Password meets high security standards!"]
    }


# ===================================================================
# 2. PASSWORD & PASSPHRASE GENERATOR
# ===================================================================

def generate_random_password(length=16):
    """
    Generates a cryptographically secure random password using Python's secrets module.
    """
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    symbols = "!@#$%^&*()-_=+"

    # Guarantee at least one of each
    chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols)
    ]

    all_pool = lower + upper + digits + symbols
    for _ in range(length - len(chars)):
        chars.append(secrets.choice(all_pool))

    # Shuffle securely using Fisher-Yates with secrets
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def generate_passphrase(num_words=4):
    """
    Generates a high-entropy memorable passphrase (NIST SP 800-63B style).
    e.g. 'Dragon-Crystal-Falcon-Summit-48!'
    """
    words = [secrets.choice(PASSPHRASE_WORDS).capitalize() for _ in range(num_words)]
    num = secrets.randbelow(900) + 100
    sym = secrets.choice("!#*&$%")
    return f"{'-'.join(words)}-{num}{sym}"


def suggest_alternatives(base_password):
    """
    Produces smart stronger suggestions based on user input.
    """
    suggestions = [
        ("Cryptographic Random Password", generate_random_password(16)),
        ("Memorable Diceware Passphrase", generate_passphrase(4))
    ]

    if base_password:
        # Enhanced mutation of the user's password
        sym1 = secrets.choice("!@#$%^&*")
        sym2 = secrets.choice("!@#$%^&*")
        num = secrets.randbelow(900) + 100
        mutated = f"{sym1}{base_password.capitalize()}_{num}{sym2}"
        suggestions.append(("Hardened Variant of Your Password", mutated))

    return suggestions


# ===================================================================
# 3. DATABASE INTEGRATION & REUSE PREVENTION
# ===================================================================

DB_FILE = "passwords.db"
HISTORY_LIMIT = 5  # Prevent reusing the last 5 passwords
PBKDF2_ITERATIONS = 100_000


def init_database():
    """
    Initializes the SQLite database with users and password history tables.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            salt_hex TEXT NOT NULL,
            iterations INTEGER NOT NULL,
            algorithm TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()


def hash_password_with_salt(password, salt_hex, iterations=PBKDF2_ITERATIONS):
    """
    Hashes password with salt using PBKDF2-HMAC-SHA256 (100,000 iterations).
    """
    salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)
    return derived.hex()


def save_password_with_reuse_check(username, password):
    """
    Checks if password was used in the last 5 entries for this user.
    If not, hashes with a new random salt and stores in database.
    """
    init_database()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Get or create user
    cursor.execute("SELECT id FROM users WHERE username = ?", (username.lower(),))
    user_row = cursor.fetchone()
    if not user_row:
        cursor.execute("INSERT INTO users (username) VALUES (?)", (username.lower(),))
        conn.commit()
        user_id = cursor.lastrowid
    else:
        user_id = user_row[0]

    # Fetch last 5 password history records
    cursor.execute("""
        SELECT salt_hex, password_hash, iterations, created_at
        FROM password_history
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
    """, (user_id, HISTORY_LIMIT))
    history = cursor.fetchall()

    # Verify against previous passwords
    for salt_hex, stored_hash, iters, created_at in history:
        candidate_hash = hash_password_with_salt(password, salt_hex, iters or PBKDF2_ITERATIONS)
        # Constant-time comparison to prevent timing attacks
        if secrets.compare_digest(candidate_hash, stored_hash):
            conn.close()
            return {
                "success": False,
                "reused": True,
                "message": f"SECURITY ALERT: Password was already used on {created_at}! Reusing recent passwords violates security policy."
            }

    # If not reused, generate 128-bit random salt and store
    new_salt = secrets.token_hex(16)
    new_hash = hash_password_with_salt(password, new_salt, PBKDF2_ITERATIONS)

    cursor.execute("""
        INSERT INTO password_history (user_id, password_hash, salt_hex, iterations, algorithm)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, new_hash, new_salt, PBKDF2_ITERATIONS, 'PBKDF2-HMAC-SHA256'))
    conn.commit()
    conn.close()

    return {
        "success": True,
        "reused": False,
        "message": "Password accepted! Hashed with unique 128-bit salt and stored in SQLite.",
        "salt_preview": f"{new_salt[:8]}...{new_salt[-8:]}",
        "hash_preview": f"{new_hash[:12]}...{new_hash[-12:]}"
    }


def view_password_history(username):
    """
    Returns non-sensitive audit records showing that only salted hashes are stored.
    """
    init_database()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username.lower(),))
    user_row = cursor.fetchone()
    if not user_row:
        conn.close()
        return []

    cursor.execute("""
        SELECT id, salt_hex, password_hash, created_at
        FROM password_history
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 10
    """, (user_row[0],))
    rows = cursor.fetchall()
    conn.close()
    return rows


# ===================================================================
# 4. EDUCATIONAL CRYPTOGRAPHY EXPLANATION
# ===================================================================

def display_cryptography_concepts():
    print("""
========================================================================
   KEY CONCEPTS: PASSWORD SECURITY & CRYPTOGRAPHY
========================================================================
1. Hashing vs. Encryption vs. Encoding:
   - Encoding (e.g. Base64): NOT security. Easily reversed back to plaintext.
   - Encryption (AES, RSA): Two-way. Scrambles data with a secret key.
   - Hashing (SHA-256): One-way. Mathematically irreversible.

2. Why Plain Hashes are Vulnerable (Rainbow Tables):
   - Attackers precompute trillions of common password hashes into lookup
     tables called 'Rainbow Tables'. If your password hash matches, they
     crack it in 0.001 seconds!

3. The Power of Cryptographic Salt:
   - A 'Salt' is a cryptographically random string (e.g. 16 bytes) added
     to each password before hashing: Hash(Salt + Password).
   - Because every user gets a completely unique salt, precomputed
     Rainbow Tables are rendered 100% useless!

4. Work Factor / Slow Hashes (PBKDF2, bcrypt, Argon2):
   - Fast hashes (like raw MD5 or SHA-256) run at 100 Billion guesses/sec on GPUs.
   - Password hashing uses key derivation (like PBKDF2 with 100,000 rounds)
     to force attackers to spend heavy compute time per guess.

5. NIST SP 800-63B Recommendation:
   - Memorable multi-word passphrases (e.g. 'Dragon-Crystal-Falcon-Summit-48!')
     provide superior length and entropy while being easy for humans to remember.
========================================================================
""")


# ===================================================================
# 5. INTERACTIVE CLI INTERFACE
# ===================================================================

def print_report(res):
    print("\n" + "=" * 55)
    print(" [PASSWORD STRENGTH EVALUATION REPORT]")
    print("=" * 55)
    print(f"Target Password : {res['password']}")
    print(f"Rating          : [{res['rating'].upper()}]")
    print(f"Security Score  : {res['score']} / 100")
    print(f"Length          : {res['length']} characters")
    print(f"Search Pool (R) : {res['pool_size']} characters")
    print(f"Entropy         : {res['entropy_bits']} bits")
    print(f"Est. Crack Time : {res['crack_time']} (at 100B guesses/sec)")
    print("-" * 55)
    print("Checklist:")
    for check_name, passed in res['checks'].items():
        symbol = "[PASS]" if passed else "[FAIL]"
        print(f"  {symbol:<7} {check_name}")

    if res['vulnerabilities']:
        print("\n[!] Vulnerabilities Detected:")
        for v in res['vulnerabilities']:
            print(f"   - {v}")

    if res['recommendations']:
        print("\n[*] Recommendations:")
        for r in res['recommendations']:
            print(f"   - {r}")
    print("=" * 55)


def main():
    # If user provided password as command line argument: python password_analyzer.py "MyPass123!"
    if len(sys.argv) > 1:
        pwd = sys.argv[1]
        res = analyze_password(pwd)
        print_report(res)
        sys.exit(0)

    print("\n=============================================================")
    print("   CYBERSHIELD: Python Password Strength Analyzer")
    print("   Evaluates Length, Complexity, Uniqueness & Prevents Reuse")
    print("=============================================================")

    while True:
        print("\nMain Menu:")
        print("1. Analyze Password Strength")
        print("2. Generate Strong Password Alternatives")
        print("3. Save Password with Database Reuse Policy (SQLite)")
        print("4. View Password History Audit Log (Salted Hashes)")
        print("5. Learn Cryptography & Password Security Concepts")
        print("6. Exit")

        try:
            choice = input("\nSelect an option (1-6): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting. Stay secure!")
            break

        if choice == "1":
            pwd = input("\nEnter password to evaluate: ")
            res = analyze_password(pwd)
            print_report(res)

            alts = suggest_alternatives(pwd)
            print("\nSuggested Stronger Alternatives:")
            for title, alt_pwd in alts:
                print(f"  * {title}:")
                print(f"    --> {alt_pwd}")

        elif choice == "2":
            print("\nGenerating alternatives:")
            rand_pwd = generate_random_password(18)
            passphrase = generate_passphrase(4)
            print(f"\n1. Cryptographic Random (18 chars): {rand_pwd}")
            print(f"2. Memorable Diceware Passphrase  : {passphrase}")

        elif choice == "3":
            username = input("\nEnter username/account: ").strip()
            if not username:
                print("Username cannot be empty.")
                continue
            pwd = input("Enter new candidate password: ")
            if not pwd:
                print("Password cannot be empty.")
                continue

            result = save_password_with_reuse_check(username, pwd)
            if result["success"]:
                print(f"\n[OK] SUCCESS: {result['message']}")
                print(f"   Stored Salt Preview : {result['salt_preview']}")
                print(f"   Stored Hash Preview : {result['hash_preview']}")
            else:
                print(f"\n[DENIED] {result['message']}")

        elif choice == "4":
            username = input("\nEnter username to check history: ").strip()
            rows = view_password_history(username)
            if not rows:
                print(f"\nNo history found for '{username}'.")
            else:
                print(f"\nAudit Log for '{username}' (Last 5 Passwords):")
                print("-" * 65)
                print(" # | Date Created        | Salt (Hex)       | Stored Hash (Preview)")
                print("-" * 65)
                for idx, row in enumerate(rows, 1):
                    pid, salt, hash_val, created = row
                    print(f" {idx} | {created[:19]} | {salt[:8]}... | {hash_val[:16]}...")
                print("-" * 65)
                print("Note: Passwords are NEVER stored in plaintext. Only salted hashes!")

        elif choice == "5":
            display_cryptography_concepts()

        elif choice == "6":
            print("\nExiting CyberShield. Stay secure!\n")
            break
        else:
            print("Invalid selection. Please choose 1-6.")


if __name__ == "__main__":
    main()
