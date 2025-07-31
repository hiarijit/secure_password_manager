# 🔐 Secure Password Manager

This is a Flask-based secure password manager that allows users to register, log in, and store their passwords securely using encryption. It supports user authentication and encrypted export of vault data.

## Features

- User registration and login
- AES encryption for storing passwords securely
- Secure key export (with authentication)
- CSRF protection (can be disabled for API-like use)
- SQLite database support

## Requirements

- Python 3.12+
- Flask
- Flask-Login
- Flask-WTF
- Flask-SQLAlchemy
- Cryptography

## Setup

```bash
# Create virtual environment
python -m venv env
source env/bin/activate  # or env\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Run the app
python run.py
```


## Security Notes

Use .env to store your SECRET_KEY securely.
Make sure to secure the encryption key on production deployments.
CSRF is enabled by default; disable only when you trust all input sources.

## License

MIT
