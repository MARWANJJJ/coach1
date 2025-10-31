# Coach Backend + Site

This workspace contains a simple Express backend (auth + subscriptions storage) and the single-file frontend `coach.html`.

Features
- POST /api/subscriptions — public endpoint to create subscription requests
- POST /api/auth/login — admin login, returns JWT
- GET /api/subscriptions — protected, returns all subscriptions
- POST /api/subscriptions/:id/status — protected, update subscription status (approved/rejected)
- Static server: serves `coach.html` and assets from project root

Quick start
1. Copy `.env.example` to `.env` and set ADMIN_USER, ADMIN_PASS, JWT_SECRET

2. Install dependencies:

```powershell
cd "c:\Users\panda\OneDrive\Desktop\New folder"
npm install
```

3. Start server:

```powershell
npm start
# or for development (requires nodemon): npm run dev
```

4. Open the site in your browser:

http://localhost:3000/coach.html

Admin
- Login via the admin modal in the page. Use the username/password set in `.env`.
- Once logged in you'll be able to see subscriptions and approve/reject them. Approve/Reject will call the backend to update the record.

Notes
- Subscriptions are stored in `subscriptions.json` in the project root. It's a simple JSON file for demo purposes. For production, migrate to a database.
- JWT secret must be kept private.
- This backend is minimal and intended for local or small deployments. For production, add HTTPS, proper session handling and CSRF protections.
