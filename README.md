# Password Strength Analyzer

A cybersecurity tool that analyzes password strength in real time — entropy calculation, crack time estimation, pattern detection, and actionable feedback.

## Features
- Entropy-based strength scoring
- Crack time estimation (fast offline attack benchmark)
- Pattern detection: keyboard walks, sequences, common passwords, years, months
- Character set analysis (uppercase, lowercase, digits, symbols)
- Actionable suggestions
- Public REST API

## Stack
Python 3, Flask, Gunicorn

## Setup
```bash
git clone https://github.com/djareddirdjad/password-strength-analyzer
cd password-strength-analyzer
pip install -r requirements.txt
python app.py
```

## API
```
POST /api/analyze
Content-Type: application/json
{"password": "yourpassword"}
```

Built by [djareddirdjad](https://github.com/djareddirdjad)
