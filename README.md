# FastAPI User Authentication

This project implements a minimal user authentication system built with FastAPI. It supports email/password sign up, email verification, JWT-based login, token refresh, optional two factor authentication, and social logins with Google or Facebook. User actions are recorded in an audit log and can be queried through the API.

## Project Structure

```
app/                Application package
  core/             Configuration, dependencies, security helpers
  database/         SQLAlchemy models and session management
  modules/
    auth/           Registration, login and 2FA logic
    users/          Endpoints related to user management
    audit/          Activity logging
  tests/            Pytest unit tests
run.py              Helper to initialise the database
requirements.txt    Python dependencies
```

## Setup

1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install httpx==0.24 python-multipart email-validator
   ```
3. Copy `.env` and update values as needed. Required variables are defined in `app/core/config.py`:
   ```env
   DATABASE_URL=postgresql://postgres:postgres@localhost:5432/auth_db
   SECRET_KEY=supersecretkey
   ACCESS_TOKEN_EXPIRE_MINUTES=30
   ALGORITHM=HS256
   REDIS_URL=redis://localhost:6379
   GOOGLE_CLIENT_ID=
   GOOGLE_CLIENT_SECRET=
   FACEBOOK_CLIENT_ID=
   FACEBOOK_CLIENT_SECRET=
   ```
4. Ensure Postgres and Redis are running (see `docker-compose.yml` for reference). Create database tables by running:
   ```bash
   python run.py
   ```
5. Launch the API:
   ```bash
   uvicorn app.main:app --reload
   ```

## API Endpoints

- `POST /auth/register` – Register a new user
- `POST /auth/verify` – Verify email address
- `POST /auth/login` – Obtain access & refresh tokens
- `POST /auth/refresh` – Refresh an expired access token
- `POST /auth/logout` – Revoke an issued token
- `GET /auth/me` – Get the currently authenticated user
- `POST /auth/google` – Login via Google OAuth2
- `POST /auth/facebook` – Login via Facebook OAuth2
- `POST /auth/2fa/setup` – Generate a TOTP secret for two factor auth
- `POST /auth/2fa/enable` – Enable 2FA using an OTP code
- `POST /auth/2fa/disable` – Disable 2FA using an OTP code
- `GET /users/` – List users (admin only)
- `GET /users/{user_id}/logs` – Retrieve audit logs for a user
- `GET /audit/users/{user_id}` – Same as above via audit router

See `app/README.md` for a shorter overview of core endpoints.

## Running Tests

Execute the test suite with:
```bash
pytest -q
```

## Development Utilities

A small helper script `dev/generate_otp.py` can generate one-time passwords for testing two factor authentication:
```bash
python dev/generate_otp.py <TOTP_SECRET>
```
