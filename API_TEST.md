# API_TEST.md

Copy the URL, set the method, paste the payload, send.

Server must be running: `python run.py`

**Every request except 1, 2 and 20 needs this header:**

```
Authorization: Bearer PASTE_ACCESS_TOKEN_HERE
```

In Postman: **Headers** tab → Key `Authorization` → Value `Bearer eyJhbGci...`
For any request with a payload: **Body** → **raw** → select **JSON** in the dropdown.

The access token expires in **5 minutes**. When you get `401`, redo request **1**.

---

# 1. LOGIN (get your token first)

**Method:** `POST`

```
http://127.0.0.1:8080/api/v1/auth/login/json
```

**Payload:**

```json
{
  "username": "superadmin",
  "password": "PASTE_YOUR_FIRST_SUPERADMIN_PASSWORD"
}
```

**Response 200** — copy `access_token`, that is your Bearer token:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 300,
  "access_token_expires_at": "2026-08-19T11:20:00Z",
  "refresh_token_expires_at": "2026-08-20T11:15:00Z"
}
```

---

# 2. REGISTER A USER (superadmin only)

**Method:** `POST`

```
http://127.0.0.1:8080/api/v1/users
```

**Payload — manager:**

```json
{
  "username": "jane.manager",
  "email": "jane@example.com",
  "full_name": "Jane Manager",
  "password": "Manager123",
  "role": "manager",
  "is_active": true
}
```

**Payload — admin:**

```json
{
  "username": "alex.admin",
  "email": "alex@example.com",
  "full_name": "Alex Admin",
  "password": "Admin12345",
  "role": "admin",
  "is_active": true
}
```

**Payload — supervisor:**

```json
{
  "username": "sam.supervisor",
  "email": "sam@example.com",
  "full_name": "Sam Supervisor",
  "password": "Super12345",
  "role": "supervisor",
  "is_active": true
}
```

**Payload — visitor:**

```json
{
  "username": "vic.visitor",
  "email": "vic@example.com",
  "full_name": "Vic Visitor",
  "password": "Visitor123",
  "role": "visitor",
  "is_active": true
}
```

**Response 201:**

```json
{
  "id": 2,
  "username": "jane.manager",
  "email": "jane@example.com",
  "full_name": "Jane Manager",
  "role": "manager",
  "is_active": true,
  "created_at": "2026-08-19T11:20:00Z",
  "updated_at": "2026-08-19T11:20:00Z",
  "permissions": ["read", "update", "write"]
}
```

**Rules:** `role` = `superadmin` / `admin` / `manager` / `supervisor` / `visitor`.
Password = 8-72 chars with **at least one letter and one digit**. Username and email must be unique.

---

# 3. LOGIN AS THE NEW USER

**Method:** `POST`

```
http://127.0.0.1:8080/api/v1/auth/login/json
```

**Payload:**

```json
{
  "username": "jane.manager",
  "password": "Manager123"
}
```

---

# 4. WHO AM I

**Method:** `GET`

```
http://127.0.0.1:8080/api/v1/auth/me
```

**Payload:** none

---

# 5. MY PERMISSIONS

**Method:** `GET`

```
http://127.0.0.1:8080/api/v1/auth/me/permissions
```

**Payload:** none

**Response 200:**

```json
{ "role": "superadmin", "permissions": ["delete", "read", "role:manage", "update", "user:register", "write"] }
```

---

# 6. LIST ALL USERS

**Method:** `GET`

```
http://127.0.0.1:8080/api/v1/users?skip=0&limit=50
```

**Payload:** none

**Filtered versions:**

```
http://127.0.0.1:8080/api/v1/users?role=manager
```

```
http://127.0.0.1:8080/api/v1/users?is_active=true
```

```
http://127.0.0.1:8080/api/v1/users?search=jane
```

---

# 7. GET ONE USER

**Method:** `GET`

```
http://127.0.0.1:8080/api/v1/users/2
```

**Payload:** none

---

# 8. CHECK USER EXISTS (no body returned)

**Method:** `HEAD`

```
http://127.0.0.1:8080/api/v1/users/2
```

**Payload:** none
**Response 204** — see the `X-Resource-Role` header.

---

# 9. UPDATE USER — FULL REPLACE

**Method:** `PUT`

```
http://127.0.0.1:8080/api/v1/users/2
```

**Payload (both fields required):**

```json
{
  "email": "jane.updated@example.com",
  "full_name": "Jane Updated"
}
```

---

# 10. UPDATE USER — PARTIAL

**Method:** `PATCH`

```
http://127.0.0.1:8080/api/v1/users/2
```

**Payload (send only what you want changed):**

```json
{
  "full_name": "Jane Patched"
}
```

**Or change the email:**

```json
{
  "email": "jane.new@example.com"
}
```

**Or change the password:**

```json
{
  "password": "NewPass1234"
}
```

---

# 11. CHANGE A USER'S ROLE

**Method:** `PATCH`

```
http://127.0.0.1:8080/api/v1/users/2/access
```

**Payload — change role:**

```json
{
  "role": "admin"
}
```

**Payload — deactivate the account:**

```json
{
  "is_active": false
}
```

**Payload — both at once:**

```json
{
  "role": "supervisor",
  "is_active": true
}
```

**Note:** after a role change, that user's old token stops working (`401`) — they must log in again.

---

# 12. WHAT METHODS CAN MY ROLE USE (users)

**Method:** `OPTIONS`

```
http://127.0.0.1:8080/api/v1/users
```

**Payload:** none
**Response 204** — see the `Allow` header.

---

# 13. DELETE A USER

**Method:** `DELETE`

```
http://127.0.0.1:8080/api/v1/users/5
```

**Payload:** none
**Response 204**

---

# 14. CREATE AN ITEM

**Method:** `POST`

```
http://127.0.0.1:8080/api/v1/items
```

**Payload:**

```json
{
  "name": "Wireless Keyboard",
  "description": "Mechanical, 87 keys",
  "quantity": 12,
  "price": 49.99,
  "is_active": true
}
```

**Minimal payload (only name is required):**

```json
{
  "name": "Mouse Pad"
}
```

**Response 201:**

```json
{
  "name": "Wireless Keyboard",
  "description": "Mechanical, 87 keys",
  "quantity": 12,
  "price": 49.99,
  "is_active": true,
  "id": 1,
  "owner_id": 1,
  "created_at": "2026-08-19T11:25:00Z",
  "updated_at": "2026-08-19T11:25:00Z"
}
```

---

# 15. LIST ALL ITEMS

**Method:** `GET`

```
http://127.0.0.1:8080/api/v1/items?skip=0&limit=50
```

**Payload:** none

**Filtered versions:**

```
http://127.0.0.1:8080/api/v1/items?search=keyboard
```

```
http://127.0.0.1:8080/api/v1/items?owner_id=1
```

```
http://127.0.0.1:8080/api/v1/items?is_active=true
```

---

# 16. GET ONE ITEM

**Method:** `GET`

```
http://127.0.0.1:8080/api/v1/items/1
```

**Payload:** none

---

# 17. CHECK ITEM EXISTS (no body returned)

**Method:** `HEAD`

```
http://127.0.0.1:8080/api/v1/items/1
```

**Payload:** none
**Response 204** — see the `X-Resource-Updated-At` header.

---

# 18. UPDATE ITEM — FULL REPLACE

**Method:** `PUT`

```
http://127.0.0.1:8080/api/v1/items/1
```

**Payload (anything you leave out resets to its default):**

```json
{
  "name": "Wireless Keyboard MK2",
  "description": "Replaced via PUT",
  "quantity": 20,
  "price": 59.99,
  "is_active": true
}
```

---

# 19. UPDATE ITEM — PARTIAL

**Method:** `PATCH`

```
http://127.0.0.1:8080/api/v1/items/1
```

**Payload (send only what changes):**

```json
{
  "quantity": 7
}
```

**Or:**

```json
{
  "price": 39.99,
  "is_active": false
}
```

---

# 20. WHAT METHODS CAN MY ROLE USE (items)

**Method:** `OPTIONS`

```
http://127.0.0.1:8080/api/v1/items
```

**Payload:** none
**Response 204** — see the `Allow` header.

---

# 21. DELETE AN ITEM

**Method:** `DELETE`

```
http://127.0.0.1:8080/api/v1/items/1
```

**Payload:** none
**Response 204**

---

# 22. REFRESH THE TOKEN (when it expires)

**Method:** `POST`

```
http://127.0.0.1:8080/api/v1/auth/refresh
```

**Payload — paste the `refresh_token` you got in step 1:**

```json
{
  "refresh_token": "PASTE_REFRESH_TOKEN_HERE"
}
```

**Note:** one use only. It returns a NEW refresh token — use that one next time.

---

# 23. CHANGE MY OWN PASSWORD

**Method:** `PATCH`

```
http://127.0.0.1:8080/api/v1/auth/me/password
```

**Payload:**

```json
{
  "current_password": "PASTE_CURRENT_PASSWORD",
  "new_password": "NewSuperPass123"
}
```

---

# 24. LOGOUT

**Method:** `POST`

```
http://127.0.0.1:8080/api/v1/auth/logout
```

**Payload:**

```json
{
  "refresh_token": "PASTE_REFRESH_TOKEN_HERE"
}
```

---

# 25. HEALTH CHECK (no token needed)

**Method:** `GET`

```
http://127.0.0.1:8080/health
```

**Payload:** none

**Response 200:**

```json
{
  "status": "ok",
  "application": "Private API",
  "version": "1.0.0",
  "database": "ok",
  "authentication": "enabled",
  "authorization": "enabled"
}
```

---

# 26. LOGIN — FORM VERSION (for Swagger / OAuth2 clients)

**Method:** `POST`

```
http://127.0.0.1:8080/api/v1/auth/login
```

**Body → x-www-form-urlencoded** (NOT raw JSON):

| Key | Value |
|-----|-------|
| `username` | `superadmin` |
| `password` | your password |

---

# ROLE PERMISSIONS

| Role | read | write (POST) | update (PUT/PATCH) | delete | register users | change roles |
|------|:----:|:----:|:----:|:----:|:----:|:----:|
| superadmin | yes | yes | yes | yes | **yes** | yes |
| admin | yes | yes | yes | yes | no | yes |
| manager | yes | yes | yes | no | no | no |
| supervisor | yes | yes | no | no | no | no |
| visitor | yes | no | no | no | no | no |

Test it: log in as `jane.manager` (step 3), then try step 21 (DELETE item) → **403**.

---

# STATUS CODES

| Code | Meaning |
|:----:|---------|
| 200 | OK (GET, PUT, PATCH, logout, password change) |
| 201 | Created (user, item) |
| 204 | OK, no body (DELETE, HEAD, OPTIONS) |
| 401 | No token / bad token / expired token / wrong password / role changed |
| 403 | Your role is not allowed to do this |
| 404 | User or item does not exist |
| 409 | Username or email already exists |
| 422 | Bad payload, or a rule blocked it |

---

# IF SOMETHING FAILS

| Problem | Fix |
|---------|-----|
| Login gives `401` with the password from `.env` | Changing `.env` does not update an existing account. Run `python -m app.cli sync-superadmin`, then log in |
| Everything gives `401` after a few minutes | Token expired (5 min) — redo step 1 |
| `401` right after changing someone's role | That user's old token is dead by design — log in again |
| `401` on refresh | That refresh token was already used or logged out |
| `422` on step 1 | You used the form URL with a JSON body — use `/auth/login/json` for JSON |
| `422` saying "valid dictionary" | Body dropdown says `Text` — change it to `JSON` |
| `403` on register | You are not logged in as superadmin |
| Cannot connect | Server not running, or not on port 8080 |
| Forgot a password | `python -m app.cli reset-password --username jane` |
| Need a user without the API | `python -m app.cli create-user --username bob --email bob@x.com --role manager` |
