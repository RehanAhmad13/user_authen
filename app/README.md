# User Authentication System

This project provides a minimal FastAPI-based authentication system using OAuth2 password flow and JWT tokens. Users can register, log in to receive access and refresh tokens, refresh their access token, and retrieve their profile via protected routes.

## Setup
1. Install dependencies:
```bash
pip install -r requirements.txt
pip install httpx==0.24 python-multipart email-validator
```
2. Set environment variables via `.env` (see `app/core/config.py` for required variables).
3. Create the database tables:
```bash
python run.py
```
4. Run the API:
```bash
uvicorn app.main:app --reload
```

## Endpoints
- `POST /auth/register` – Create a new user.
- `POST /auth/login` – Authenticate with email/password and receive JWT access and refresh tokens.
- `POST /auth/refresh` – Refresh expired access tokens using a valid refresh token.
- `GET /auth/me` – Retrieve the currently authenticated user.

## Running Tests
Execute unit tests with:
```bash
pytest -q
```
