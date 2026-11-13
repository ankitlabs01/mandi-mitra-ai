# Mandi Mitra AI — Phase 4

Phase 4 adds a frontend registration/login experience connected to the existing FastAPI authentication endpoints.

## Run backend (PowerShell)
From the `backend` directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

If the virtual environment already exists, skip the `py -m venv .venv` command.

## Run frontend
Open the project root in VS Code and use Live Server on `index.html`. Keep the backend terminal running. The frontend calls `http://127.0.0.1:8000/api`.

## Test
1. Open the frontend through Live Server.
2. Choose **Create account** and register using a unique email and a password of at least 8 characters. Roles supported by this demo: farmer, buyer, FPO.
3. You should enter the workspace after successful registration.
4. Log out, then log back in with the same credentials.
5. Refresh while logged in; the stored token is checked against `/api/auth/me`.

## Important limitations
This is a local development prototype. The token is stored in browser localStorage, which is convenient for a demo but not the strongest production storage strategy. The current crop and listing endpoints in this project are not yet scoped by authenticated user, so different accounts may see the same shared demo records. Do not deploy this as a production service until authorization, per-user data ownership, rate limiting, HTTPS, secret management, and security review are implemented. Market values and buyer profiles remain illustrative demo data.
