# Password KDF Tool

A Python toolkit for **password-based key derivation**, **password hashing**, and **password strength analysis**. It is intended for learning, local testing, and as a building block for applications that need OWASP-aligned defaults and well-documented cryptography APIs.

The core logic lives in a single importable module. A small **Flask** web UI and an **interactive CLI** let you try your own passwords locally and see PBKDF2, bcrypt, scrypt, and strength metrics in one place.

---

## What this project does

| Area | Description |
|------|-------------|
| **PBKDF2** | Derive keys with **PBKDF2-HMAC-SHA256** (`cryptography`). Minimum **100,000** iterations enforced; default **300,000**. Salts must be **≥ 16 bytes** (use `generate_salt()`). |
| **bcrypt** | Hash and verify passwords with the **`bcrypt`** package. Minimum cost **12**; default **12**. |
| **scrypt** | Derive keys with **scrypt** (`cryptography`). Defaults: **N = 2¹⁵**, **r = 8**, **p = 1** (tunable). |
| **Strength** | Score (0–100), rating label, entropy estimate, and recommendations: length, character classes, common-password checks, and simple pattern penalties. |

Constant-time comparisons are used where appropriate (e.g. PBKDF2/scrypt key verification via `cryptography`’s `constant_time.bytes_eq`; bcrypt uses `bcrypt.checkpw`).

---

## Requirements

- **Python 3.9+** recommended (uses type hints and standard library features common in 3.9+).
- Dependencies are listed in `requirements.txt`:

  - `cryptography` — PBKDF2 and scrypt
  - `bcrypt` — bcrypt hashing and verification
  - `flask` — local web tester (`app.py`)

---

## Installation

From the project directory:

```bash
pip install -r requirements.txt
```

---

## Quick start

### 1. Interactive terminal (hidden password)

Runs PBKDF2, bcrypt, scrypt checks and strength analysis after you type a password (input is hidden when the terminal supports it):

```bash
python password_kdf_module.py
```

You will see output similar to:

- PBKDF2 key length and verify result  
- bcrypt hash string and verify result  
- scrypt key length and verify result  
- Strength score, rating, entropy bits, and recommendations  

### 2. Local web UI

Start the Flask app (binds only to localhost):

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000), enter a password, and submit. The page shows the same style of report. **Nothing is sent to a remote service**; processing happens in your local Python process.

### 3. Use as a library

```python
from password_kdf_module import (
    generate_salt,
    derive_key_pbkdf2,
    verify_key_pbkdf2,
    hash_password_bcrypt,
    verify_password_bcrypt,
    derive_key_scrypt,
    verify_key_scrypt,
    evaluate_password_strength,
    generate_password_report,
)

# One-shot local report (PBKDF2 + bcrypt + scrypt + strength)
report = generate_password_report("your-password")
print(report)

# Or step-by-step, e.g. PBKDF2
salt = generate_salt()
key = derive_key_pbkdf2("your-password", salt)
assert verify_key_pbkdf2("your-password", salt, key)
```

Main entry points:

- **Salts / randomness:** `generate_salt()`
- **PBKDF2:** `derive_key_pbkdf2`, `verify_key_pbkdf2`
- **bcrypt:** `hash_password_bcrypt`, `verify_password_bcrypt`
- **scrypt:** `derive_key_scrypt`, `verify_key_scrypt`
- **Strength:** `evaluate_password_strength`, `estimate_entropy_bits`
- **Demo report:** `generate_password_report`

Errors for invalid parameters use `PasswordKDFError`.

---

## Project layout

```
password_kdf_tool/
├── password_kdf_module.py   # Core KDF, bcrypt, strength, CLI when run as main
├── app.py                   # Flask local web tester
├── requirements.txt
└── README.md
```

---

## Security notes and limitations

- **Defaults favor security over speed** (high PBKDF2 iteration count, bcrypt cost ≥ 12, memory-hard scrypt parameters). Tune for your hardware and threat model in production.
- **Python memory:** Passwords and keys exist as normal `str`/`bytes`; Python does not guarantee secure wiping of immutable strings. Avoid logging secrets.
- **Strength meter:** Entropy is an **estimate** (character-pool heuristic). It is useful for guidance, not a formal cryptographic proof of unpredictability. The built-in common-password list is **small**; production systems should use a larger blocklist and policy rules.
- **Web UI:** Intended for **local development only**. Do not expose `app.py` to the internet without HTTPS, authentication, rate limiting, and a full security review. Never reuse demo passwords in real accounts.

---

## License

No license is specified in this repository; add one if you plan to distribute the code.
