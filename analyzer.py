import re
import math
from collections import Counter

COMMON_PASSWORDS = {
    "password","123456","12345678","qwerty","abc123","monkey","1234567",
    "letmein","trustno1","dragon","baseball","iloveyou","master","sunshine",
    "ashley","bailey","passw0rd","shadow","123123","654321","superman",
    "qazwsx","michael","football","password1","password123"
}

KEYBOARD_PATTERNS = [
    "qwerty","qwertyuiop","asdfgh","asdfghjkl","zxcvbn","zxcvbnm",
    "1234567890","0987654321","abcdefgh","abcdefghij"
]

def entropy(password):
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    if charset == 0: return 0
    return len(password) * math.log2(charset)

def crack_time(ent):
    # Assumes 10 billion guesses/sec (fast offline attack)
    guesses = 2 ** ent
    seconds = guesses / 1e10
    if seconds < 1: return "instantly"
    if seconds < 60: return f"{int(seconds)} seconds"
    if seconds < 3600: return f"{int(seconds/60)} minutes"
    if seconds < 86400: return f"{int(seconds/3600)} hours"
    if seconds < 31536000: return f"{int(seconds/86400)} days"
    if seconds < 3153600000: return f"{int(seconds/31536000)} years"
    return f"{int(seconds/3153600000)} centuries"

def detect_patterns(password):
    issues = []
    p = password.lower()
    if password in COMMON_PASSWORDS or p in COMMON_PASSWORDS:
        issues.append("This is a commonly used password — immediately crackable.")
    for pattern in KEYBOARD_PATTERNS:
        if pattern in p:
            issues.append(f"Contains keyboard pattern: '{pattern}'")
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (e.g. aaa, 111).")
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', p):
        issues.append("Contains sequential characters (e.g. 123, abc).")
    if re.search(r'\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b', p):
        issues.append("Contains a month name — easy to guess.")
    if re.search(r'19[0-9]{2}|20[0-2][0-9]', password):
        issues.append("Contains a year — easy to guess.")
    return issues

def analyze(password):
    if not password:
        return {"error": "No password provided"}

    length = len(password)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    ent = entropy(password)
    patterns = detect_patterns(password)

    suggestions = []
    if length < 12:
        suggestions.append("Use at least 12 characters.")
    if not has_upper:
        suggestions.append("Add uppercase letters (A-Z).")
    if not has_lower:
        suggestions.append("Add lowercase letters (a-z).")
    if not has_digit:
        suggestions.append("Add numbers (0-9).")
    if not has_symbol:
        suggestions.append("Add symbols (!@#$%^&*).")
    if patterns:
        suggestions.append("Avoid common patterns, sequences, and dictionary words.")

    # Score 0-100
    score = 0
    score += min(length * 4, 40)
    if has_lower: score += 10
    if has_upper: score += 10
    if has_digit: score += 10
    if has_symbol: score += 15
    score -= len(patterns) * 15
    score = max(0, min(100, score))

    if score >= 80: level = "Strong"
    elif score >= 60: level = "Moderate"
    elif score >= 35: level = "Weak"
    else: level = "Very Weak"

    return {
        "length": length,
        "entropy": round(ent, 1),
        "crack_time": crack_time(ent),
        "score": score,
        "level": level,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "patterns": patterns,
        "suggestions": suggestions,
    }
