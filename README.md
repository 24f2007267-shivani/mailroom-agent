# Public HTTPS Mailroom Agent

## Important starter-project note
This is a runnable starter, not a guarantee of full marks. Hidden-case action accuracy depends on the model and prompt and must be validated against the grader feedback. Before submitting, test all schema, replay, conflict, and receipt-signature cases. The app intentionally has no real email-sending integration: a verified accepted receipt records the requested outcome only.

## Local setup (Linux / VS Code)
1. Install Python 3.11+.
2. Extract this ZIP and open the `mailroom-agent` folder in VS Code.
3. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Copy `.env.example` to `.env` and fill in your provider API key. Load variables in your shell before starting:
   ```bash
   set -a; source .env; set +a
   ```
6. Start the API:
   ```bash
   uvicorn app:app --reload --host 0.0.0.0 --port 8000
   ```
7. Health check: `http://127.0.0.1:8000/health`
8. Endpoint: `http://127.0.0.1:8000/a2a` (POST JSON).

## Deploy on Render
1. Push the project to a GitHub repository. Do not upload `.env`.
2. In Render, create a new Web Service from that repository, or use the included `render.yaml` blueprint.
3. Add `AI_API_KEY` as a secret environment variable; keep the configured persistent disk mounted at `/var/data`.
4. Deploy and wait for the service to become live.
5. Check `https://YOUR-SERVICE.onrender.com/health`.
6. Set `A2A_BASE_URL` to `https://YOUR-SERVICE.onrender.com/a2a/` if your course page asks for it.
7. Submit the endpoint URL required by the grader, normally `https://YOUR-SERVICE.onrender.com/a2a` (no credentials, query, or fragment).

## Required environment variables
- `A2A_BASE_PATH=/a2a`
- `A2A_BASE_URL=https://YOUR-SERVICE.onrender.com/a2a/`
- `DATABASE_PATH=/var/data/mailroom.sqlite3` on a persistent disk
- `AI_API_KEY` from your provider
- `AI_MODEL` supported by that provider
- `AI_BASE_URL=https://api.openai.com/v1` for OpenAI-compatible APIs

## Important hardening before graded submission
- Add a provider-specific structured-output schema and retry handling.
- Validate source schemas and action-specific required values more strictly.
- Verify commit replay body equality, not just cached evaluation response.
- Add atomic transaction/concurrency tests and request-size/output/time limits appropriate to the grader.
- Add an automated test that generates an Ed25519 key pair, signs a receipt using the exact canonical JSON contract, and checks both valid and invalid signatures.
- Confirm the host's free-tier filesystem is persistent; without a persistent disk, SQLite replay/cache state may be lost on restart.
