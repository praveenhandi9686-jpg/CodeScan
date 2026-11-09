# CodeScan — AI Code Reviewer & Bug Detection System
## Setup (Windows PowerShell)
    python -m venv venv; .\venv\Scripts\Activate.ps1
    pip install -r requirements.txt; copy .env.example .env; python app.py
## Linux/macOS
    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt && cp .env.example .env && python app.py
Open http://127.0.0.1:5000. Set a real SECRET_KEY in `.env`.
## AI (optional)
Put `AI_API_KEY`, `AI_MODEL`, `AI_API_URL` in `.env` (server-side only). The endpoint must accept OpenAI-style chat-completions requests. Without them, static analysis still runs.
## Tests
    pip install -r requirements-dev.txt
    pytest -q
## Production
Use `FLASK_ENV=production`, a strong SECRET_KEY, PostgreSQL `DATABASE_URL` (+ psycopg2), HTTPS, `gunicorn "app:create_app()"`, and a shared rate-limit store (Redis) instead of the in-memory one.

## Suggested Code
After each review, CodeScan builds a corrected version of your code (automatic fixes, upgraded by the AI when configured). The AI version is only shown if static analysis rates it at least as good. A diff and before/after score are included; nothing overwrites your editor unless you click "Load into editor".
## Output
"Run original / Run suggested" executes Python, JavaScript, Bash, Ruby and PHP (if installed) and shows stdout/stderr; HTML shows a sandboxed preview. This is NOT a hardened sandbox, so it is off unless FLASK_ENV=development or ENABLE_CODE_EXECUTION=true. Never enable it on a public server.

## Analysis engines and accuracy
Python also gets a type checker (`pytypes.py`): it infers the type of simple values (literals, int()/input()/str() results, variables assigned from them) and reports operations that will crash at runtime - int + str, str compared with int, wrong argument counts, unknown attributes, division by zero, iterating an int, undefined names with a 'did you mean' hint. Unknown types never produce a claim, and it was audited against 517 standard-library files (274k lines) with zero false alarms.
Every syntax error is reported in one review (up to 50): after each error the broken statement is neutralised and the code re-parsed, then the security/bug checks run on the repaired code, so nothing is hidden behind the first error.
Syntax errors come from real parsers (Python `ast`, tree-sitter for JS/TS/Java/C/C++/C#/Go/PHP/Ruby/Rust/Bash/Kotlin/Swift, plus built-in CSS and HTML parsers), so they are essentially exact. Security/bug findings are rule-based and carry a Confirmed/Potential/Suggestion label; expect roughly 80-90% useful results, not perfection. SQL has no parser (rules only). If a tree-sitter package is missing, that language falls back to pattern rules; the review status line shows which engine was used. `tests/corpus.py` holds the clean/buggy samples that guard accuracy: add a failing sample there whenever you find a miss.

## Accounts, reports and settings
- **Login / register** with username or email and a password.
- **Reports** download as a PDF with scores, severity chart, findings, source listing and suggested code. **Import file** reads a source file in the browser (max 200 KB).
- **Profile** shows your account data and stats; **Settings** has profile, password, full history and account deletion.

## Deploy to Vercel
1. Push this folder to GitHub (the repo root must contain `app.py`, `requirements.txt`, `public/`, `templates/`).
2. Vercel > Add New > Project > import the repo (Framework preset: Flask / Other; leave build settings empty).
3. Create a database: Vercel > Storage > Create > Neon (Postgres) > Connect to this project. It adds `DATABASE_URL` / `POSTGRES_URL` automatically.
4. Project > Settings > Environment Variables, add: `SECRET_KEY` (a random 32+ character string, required), and optionally `AI_API_KEY`, `AI_MODEL`, `AI_API_URL`.
5. Deploy. Open `https://<your-app>.vercel.app/api/health` - it should return `{"status":"ok","success":true}`.

Notes: running code (Output section) is always disabled on Vercel for security. Rate limits are per serverless instance. Without `DATABASE_URL` the app uses a temporary SQLite file in /tmp, so accounts and history are lost between invocations.

## Deploy to Render
Easiest: Render Dashboard > New > **Blueprint** > select this repo (it reads `render.yaml`: web service + Postgres, `SECRET_KEY` generated automatically).
Manual setup instead: New > Web Service > Language **Python 3**; Build Command `pip install -r requirements.txt`; Start Command `gunicorn app:app --workers 1 --threads 4 --timeout 120 --bind 0.0.0.0:$PORT`; Health Check Path `/api/health`; environment variables `FLASK_ENV=production`, `SECRET_KEY` (random 32+ chars) and `DATABASE_URL` (a Postgres URL). Python is pinned to 3.12 by `.python-version`.
Add `AI_API_KEY`, `AI_MODEL`, `AI_API_URL` under Environment to enable AI. Free plan: the service sleeps after 15 minutes idle (first request is slow) and free Postgres expires after 30 days; for permanent data put an external Postgres URL (Neon, Supabase) in `DATABASE_URL` and delete the `databases:` block.

## Run any language, compiler checks and Debug mode
- **Output section** runs Python, JavaScript, TypeScript, Java, C, C++, C#, Go, PHP, Ruby, Rust, Kotlin, Swift, Bash and SQL (compiling first where needed). HTML and CSS show a sandboxed preview (CSS is applied to a sample page). It uses the compilers/interpreters installed on YOUR computer; if one is missing the Output section says what to install. Turn running on with `FLASK_ENV=development` or `ENABLE_CODE_EXECUTION=true`; it is never available on Vercel/Render.
- **Compiler checks:** when a language's compiler is installed (gcc/g++, javac, go, rustc, tsc, php, ruby, bash, swiftc), every review also includes the compiler's real errors, including type errors. Set `COMPILER_CHECKS=false` to disable. Needs-libraries-that-are-not-installed output is ignored, not reported as your bug.
- **Debug mode** (pill in the top bar, ON by default, remembered in the browser): shows per-review diagnostics (engine, timing, compiler command and result), the steps of every run, a table of which toolchains this computer has, and API timings in the browser console. `python app.py` also runs Flask in debug mode ("Debug mode: on") unless `FLASK_DEBUG=0`.

## Pasted line numbers
Code copied from tutorials or chats often has a number on every line (`1. x = 1`, `2) y`, `3: z`, `4 | w`). If nearly every line has a number and they count up by one, CodeScan ignores them (indentation kept, report line numbers unchanged) and says so at the top of the summary. Real code such as dictionaries with numeric keys is left alone.
