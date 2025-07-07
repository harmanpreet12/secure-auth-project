## 🚀 Setting Up the Repository

Follow these steps to set up and run the project on your local machine:

### 📁 1. Clone the Repository
```bash
git clone https://github.com/YOUR-USERNAME/secure-auth-project.git
cd secure-auth-project

2. Install Dependencies
npm install

3.Generate SSL certificates:
Create a folder called ssl and run:

🛠️ 4 . Configure Environment Variables

SESSION_SECRET=your_session_secret
JWT_SECRET=your_jwt_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

▶️ 5. Run the Server
node server.js

The app will run at:
🔗 https://localhost:3000

🔍 6. Test the Application
Use tools like curl, Postman, or your browser to test:

POST /register

POST /login

GET /profile

GET /admin

POST /logout

POST /refresh-token

### 🧠 Reflection Checkpoint for PART A 

I chose to implement both **local authentication** (using email and password) and **Google Single Sign-On (SSO)** to balance security and user convenience. Google OAuth is secure and widely used, reducing friction for users who already have Google accounts. I used the `passport-google-oauth20` strategy for this, and it integrated smoothly in my development environment.

My decision was influenced by past experience using Google login in other web projects, which made the setup more familiar. For local authentication, I used `bcryptjs` to hash user passwords securely and protected sessions with HTTPS and Express session middleware. In future iterations, I plan to implement a **password reset feature** to enhance user experience and account recovery.

# 🔐 Part B: Control Access with Role-Based  Permissions

### ❓ How did you structure your access control system?

✅ I implemented a **Role-Based Access Control (RBAC)** system using Express and middleware. Each user in `users.json` has a `role` field (either `"admin"` or `"user"`).  
When a user logs in, their session includes this role. I created custom middleware to check the role before allowing access to protected routes like `/admin`.

Key structure:
- `"role"` field in user data
- `auth.js`: Verifies login session
- `authorize.js`: Checks for required roles
- Routes are protected using these middlewares

---

### ❓ What specific challenges did you face?

🔍 Major challenges included:
- Typos in `curl` commands (especially with `&` and headers)
- Debugging errors like `req.body undefined` caused by wrong `Content-Type`
- Handling HTTPS self-signed certificates locally (had to use `-k` in curl)

---

### ❓ What trade-offs did you encounter between security and user experience?

⚖️ **Security vs Usability Trade-offs:**
- Used **session cookies** for simplicity instead of JWT — easier for server-side but less scalable
- Allowed role-specific dashboards to improve user experience without exposing admin functionality
- Skipped strict HTTPS cert verification during development (in production, we’d enforce it)

---

## 🛠️ Technical Overview

### ✅ User Roles

Users are defined in `users.json` with a `role` field:

```json
{
  "id": 1751769242636,
  "username": "harman",
  "email": "preetkaurpanaich@gmail.com",
  "role": "admin"
}
✅ Testing (via curl):
# Login (admin)
curl -k -c cookies.txt -X POST https://localhost:3000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=preetkaurpanaich@gmail.com&password=Panaich@2002"

# Test access
curl -k -b cookies.txt https://localhost:3000/admin
curl -k -b cookies.txt https://localhost:3000/profile
curl -k -b cookies.txt https://localhost:3000/dashboard

🔒 Reflection on JWT Strategy for PART C
 
1. Token Storage Strategy
We chose to store both access and refresh tokens in HttpOnly cookies.
This helps protect the tokens from XSS attacks, as JavaScript cannot access these cookies.
Additionally, cookies are sent automatically with each request, ensuring secure and consistent token handling.

2. Expiry Strategy
Access Token: 15 minutes

Refresh Token: 7 days
This setup balances security (short access lifespan) and user experience (longer refresh window to stay logged in).

3. Token Refresh Flow
When the access token expires, the client sends a request to /refresh-token.
If the refresh token is still valid, a new access token is issued.
This avoids forcing the user to log in again frequently, improving usability while maintaining security.

4. Challenges Faced
A key challenge was integrating Passport's session-based Google OAuth with JWT-based authentication.
We resolved this by using Passport only for initial login (Google OAuth) and JWTs for protected route access (/profile, /dashboard, etc.).

5. Trade-Offs & Security Measures
Security vs. Usability:
A shorter access token lifespan increases security but could frustrate users. The refresh token system resolves this by extending session length without compromising safety.

HttpOnly Cookies vs. localStorage:
Although localStorage is easier to work with, it’s vulnerable to XSS.
HttpOnly cookies are safer and prevent token theft via malicious JavaScript.

---

### 🧠 Reflection Checkpoint – Part D: Mitigating Security Risks

In this section, we focused on identifying and addressing session-related vulnerabilities to strengthen our application's security.

#### 🔍 Risks Identified

* Session fixation
* Cross-Site Request Forgery (CSRF)
* Brute-force login attempts
* Session hijacking via exposed cookies

#### 🛡️ Solutions Implemented

* Regenerated session IDs after login to mitigate session fixation.
* Enabled CSRF protection using `csurf` middleware and a frontend-accessible token (`XSRF-TOKEN`).
* Applied secure cookie flags (`HttpOnly`, `Secure`, `SameSite='Strict'`) to prevent unauthorized access and cross-origin attacks.
* Introduced rate limiting on login attempts to prevent brute-force attacks and account enumeration.
* Set a session timeout (`30 minutes`) to limit exposure if a session remains idle.

#### ⚖️ Trade-offs & Usability Considerations

* Security measures like short session durations and CSRF tokens added complexity but were necessary.
* Balancing user experience with security was a challenge, especially in coordinating JWT and session-based strategies.
* We opted for HttpOnly cookies and strict CSRF enforcement to maximize backend control while requiring minimal frontend changes.

> Overall, this approach provides a secure and reliable session experience while protecting against common attack vectors, without sacrificing usability.

---

### 🧠 Reflection Checkpoint: Part E – Security Testing

To test the robustness of the authentication system, I implemented a combination of manual tests and simulated attacks. My testing strategy focused on verifying each authentication flow (local and SSO), enforcing access control with JWTs, and ensuring session security with CSRF protection and cookie attributes. I used `curl` commands and browser developer tools to validate token handling, cookie flags (`HttpOnly`, `Secure`, `SameSite`), and role-based restrictions.

During testing, I identified a CSRF-related issue where token mismatches were not being caught correctly. This was resolved by ensuring the token was consistently retrieved and sent via the `X-XSRF-TOKEN` header in all `POST` requests. I also fine-tuned the session regeneration flow to prevent session fixation by calling `req.session.regenerate()` on login.

I prioritized critical issues first—especially those involving unauthorized access, token leakage, or session hijacking—before addressing usability challenges like token expiry and refresh logic. By simulating common attacks such as brute force login attempts, CSRF, and forged JWTs, I was able to confirm that the system handles security threats effectively without sacrificing user experience.

---

🔐 Authentication Testing

Local Login/Register: Performed using curl with both valid and invalid credentials to confirm proper hashing and error responses.

Google OAuth SSO: Verified the complete login flow including callback handling and session initialization.

JWT Management: Ensured JWTs are correctly signed, stored in secure HttpOnly cookies, and validated on each protected route.

🔑 Authorization Testing

/admin: Confirmed restricted access only for users with the admin role.

/dashboard: Verified conditional content rendering based on role (admin/user).

/profile: Tested access control to allow only authenticated users.

🛡️ Security Risk Mitigation

CSRF Protection: Verified XSRF-TOKEN is included in cookies and required in headers for all state-changing requests. Rejected forged POST requests successfully.

Rate Limiting: Triggered repeated failed login attempts and confirmed rate limiter blocked further access.

Session Fixation: Confirmed session ID is regenerated on successful login to prevent fixation.

Secure Cookies: Inspected Set-Cookie headers and confirmed presence of HttpOnly, Secure, and SameSite=Strict attributes.

🧪 Manual Penetration Tests

JWT Tampering: Attempted payload modification and confirmed server rejected the token due to failed signature verification.

Invalid Refresh Tokens: Simulated expired/invalid refresh tokens and verified proper 403 Forbidden response.

Unauthorized Access: Attempted to access protected endpoints without a token and confirmed access was denied with proper 401/403 status codes

🔐 Authentication Mechanisms for PART F 
Our secure authentication system includes both local login and Google OAuth 2.0 SSO:

Local Authentication:
Users can register with a username, email, and password. Passwords are hashed using bcrypt before being stored securely in users.json. On login, credentials are verified and sessions are initialized.

Google OAuth SSO:
Users can also log in using their Google account. This is implemented via Passport.js with the Google strategy. On successful login, the user session is established just like with local auth.

Session Management:
We use express-session to manage user sessions. Sessions are stored in secure cookies with Secure, HttpOnly, and SameSite=Strict flags to prevent common attacks like XSS or CSRF.

JWT Tokens:
After successful login, we issue both access and refresh tokens.

The access token is short-lived (15 minutes) and sent as an HttpOnly cookie.

The refresh token lasts 7 days and is used to issue new access tokens without requiring re-login.

Tokens are validated on protected routes and roles are extracted from the JWT payload.

CSRF Protection:
Implemented using csurf. A CSRF token is sent in a cookie (XSRF-TOKEN) and must be included in a header (X-XSRF-TOKEN) for all POST/PUT/DELETE requests.

---

### 🛡️ Role-Based Access Control (RBAC) PART F

The system defines two main user roles:

* **User**:

  * Can access general user routes such as `/profile` and `/dashboard`.
  * Has limited permissions to view their own data and basic app features.

* **Admin**:

  * Has elevated privileges with access to admin-only routes such as `/admin`.
  * Can access sensitive data and perform management tasks.

**Implementation details:**

* User roles are stored as part of the user object in the database (`users.json`) and included in JWT payloads.
* Middleware verifies the user's role on protected routes before granting or refusing access.
* This strategy strikes a balance between security and usability for everyday users by limiting sensitive behaviors.

---

### 🧠 Lessons Learned

During the development of this secure authentication system, several challenges arose:

* **CSRF token synchronization issues:**
  Initially, CSRF tokens were not correctly sent or validated, causing rejected requests. This was resolved by ensuring tokens were consistently set in cookies and sent in request headers.

* **Session fixation risk:**
  Without regenerating sessions on login, sessions could be hijacked. Calling `req.session.regenerate()` after successful login mitigated this vulnerability.

* **JWT management complexity:**
 Careful planning was necessary to balance token expiration, refresh processes, and secure storage in order to prevent user annoyance or security flaws.  To assist stop XSS attacks, JWTs were stored in HttpOnly cookies.

* **Rate limiting and brute force protection:**
Rate restriction on login routes was necessary to stop credential stuffing attacks, but it needed to be adjusted to keep legitimate users from being locked out.

* **Role-based access nuances:**
In order to prevent permission escalation and preserve a seamless user experience, iterations were necessary to design transparent, maintainable role checks.

All things considered, the phase improved knowledge of secure session management and the value of testing edge cases, particularly when it comes to token and session handling.

 | Feature                        | ✅ Working |
| ------------------------------ | --------- |
| Local login with password      | ✅ Yes     |
| CSRF protection via token      | ✅ Yes     |
| JWT issued and stored securely | ✅ Yes     |
| Role-based access (`/profile`) | ✅ Yes     |
| Session and cookie security    | ✅ Yes     |
