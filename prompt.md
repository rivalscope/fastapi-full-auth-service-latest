
> **System (or “You are …”)**  
> You are an expert FastAPI / OpenAPI architect.
>  
> **Task:** Transform this FASTAPI_AUTH_SERVICE as follows:

> 1. Replaces every `token` **query parameter** with a standard HTTP-Bearer header named `Authorization` (`Bearer <opaque-token>`).  
> 2. Deletes the **TokenVerify** request-body schema and instead makes `/verify` accept **both**  
>    * the `Authorization` header (user token) **and**  
>    * an `X-Service-Token` header (internal service credential).  
> 3. Adds two security schemes under `components.securitySchemes`:
>    ```yaml
>    userAuth:
>      type: http
>      scheme: bearer
>      bearerFormat: OPAQUE      # short-lived user key
>    serviceAuth:
>      type: apiKey
>      in: header
>      name: X-Service-Token     # only inter-service hops add this
>    ```
> 4. Applies **`userAuth` globally** to every operation via the root-level `security:` field, then:
>    * Leaves `/login`, `/register`, `/recovery`, `/` (root) **public** by overriding with `security: []`.  
>    * Makes `/verify` require **both** headers (AND semantics):
>      ```yaml
>      security:
>        - userAuth: []
>          serviceAuth: []
>      ```

### What you sneed to do  on each file you modify

| Step | Action |
|------|--------|
| **Delete** | every `parameters: - name: token in: query …` block |
| **Delete** | the `TokenVerify` request-body schema and the body description under `/verify` (because the credentials are now headers) |
| **Add** | the `components.securitySchemes` block above |
| **Add** | the top-level `security:` list (`- userAuth: []`) |
| **Override** | public endpoints with `security: []` as shown |
| **Override** | `/verify` with the combined `userAuth + serviceAuth` object |

---

How shall look when is completed

* 🔒 **Authorize** button shows **two** input boxes:  
  *User token* (Bearer) and *X-Service-Token* (only needed when you test `/verify`).  
* Once you click **Authorize**, Swagger UI attaches the bearer header to every “Try it out” request—no more copying tokens into query strings or JSON bodies.

API is now idiomatic, stateless, and compatible with FastAPI’s built-in `HTTPBearer` / `APIKeyHeader` dependencies.



> **Input spec begins**

Below is the **minimal OpenAPI skeleton** you should merge into the real application structure.

---

```yaml
openapi: 3.1.0
info:
  title: FastAPI Auth System
  version: 1.0.0

# 1️⃣  Security schemes (add once)
components:
  securitySchemes:
    userAuth:          # short-lived opaque key the browser holds
      type: http
      scheme: bearer
      bearerFormat: OPAQUE
    serviceAuth:       # internal service secret
      type: apiKey
      in: header
      name: X-Service-Token

# 2️⃣  Make *every* path protected by default
security:
  - userAuth: []       # ← this header must be present on every call

paths:
  # 3️⃣  PUBLIC ENDPOINTS – override with no security
  /login:
    post:
      security: []     # no headers needed
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/UserLogin"
      responses:
        "200":
          description: Successful Response
          content:
            application/json:
              schema: { $ref: "#/components/schemas/LoginResponse" }

  /register:
    post:
      security: []
      …

  /recovery:
    post:
      security: []
      …

  /:
    get:
      security: []
      …

  # 4️⃣  LOGOUT (was ?token=…) – now just relies on the header
  /logout:
    post:
      summary: Logout
      responses:
        "200":
          description: Successful Response

  # 5️⃣  MY ACCOUNT – header only, old query-param removed
  /my_account/:
    get:
      summary: Get Account
      responses:
        "200":
          description: Successful
          content:
            application/json:
              schema: { $ref: "#/components/schemas/UserAccountDetails" }

    put:
      summary: Update Account
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/UserUpdate" }
      responses:
        "200": { description: Successful Response }

    delete:
      summary: Delete Account
      responses:
        "200": { description: Successful Response }

  # 6️⃣  ADMIN ENDPOINTS – same pattern: no more ?token=
  /accounts_management/:
    get:
      summary: List All Users
      parameters:
        - name: skip
          in: query
          schema: { type: integer, default: 0 }
        - name: limit
          in: query
          schema: { type: integer, default: 100 }
      responses:
        "200":
          description: Successful Response
          content:
            application/json:
              schema:
                type: array
                items: { $ref: "#/components/schemas/UserInDB" }

    post:
      summary: Create User
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: "#/components/schemas/UserCreate" }
      responses:
        "201":
          description: Successful

  /accounts_management/{user_id}:
    parameters:
      - name: user_id
        in: path
        required: true
        schema: { type: integer }
    get:    { summary: Get User Details,  responses: { "200": { description: ok } } }
    put:    { summary: Update User,       responses: { "200": { description: ok } } }
    delete: { summary: Delete User,       responses: { "200": { description: ok } } }

  # 7️⃣  VERIFY – **both** headers required
  /verify:
    post:
      summary: Verify Token (inter-service)
      security:
        - userAuth: []
          serviceAuth: []   # AND semantics – both headers must be sent
      responses:
        "200":
          description: Successful Response
          content:
            application/json:
              schema: { $ref: "#/components/schemas/TokenVerifyResponse" }
```

> **Input spec ends**

