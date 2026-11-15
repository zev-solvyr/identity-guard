# 🛡️ IdentityGuard

A standalone, stateless Identity Provider (IdP) built with **Spring Boot 3** and **Spring Security**, implementing a dual-token JWT authentication architecture with strict refresh token rotation.

---

## 🚀 Key Features

* **Stateless Authentication:** Zero server-side session storage (`SessionCreationPolicy.STATELESS`) to support horizontal microservice scaling.
* **Dual-Token Architecture:** 
  * **Access Token (15 mins):** Short-lived, HMAC-SHA256 signed JWT sent in the JSON payload for high-speed authorization without database lookups.
  * **Refresh Token (7 days):** Secure UUID stored in PostgreSQL and delivered exclusively via an `HttpOnly`, `SameSite=Strict` cookie.
* **Refresh Token Rotation:** Single-use refresh tokens—every token refresh revokes the previous token and mints a fresh pair to mitigate replay attacks.
* **Security Hardening:** BCrypt password hashing, XSS mitigation via `HttpOnly` cookies, CSRF protection via `SameSite=Strict`, and path-restricted cookie transmission (`/api/auth`).
* **Version-Controlled Schema:** Database migrations managed deterministically using **Flyway** (`ddl-auto: validate`).

---

## 🛠️ Tech Stack

* **Language & Framework:** Java 21, Spring Boot 3.3.5, Spring Security, Spring Data JPA
* **Cryptography:** JJWT (`io.jsonwebtoken` 0.12.6), BCrypt
* **Database & Migrations:** PostgreSQL 15, Flyway
* **Infrastructure:** Docker, Docker Compose

---

## 🏗️ Request Flow Overview

```text
Client Request ──► SecurityFilterChain ──► JwtAuthenticationFilter
                                                │
                         ┌──────────────────────┴──────────────────────┐
                         ▼                                             ▼
            [Public: /api/auth/**]                       [Protected: /api/users/**]
            Proceeds to AuthController                   Verifies JWT Signature & Claims
            (Register / Login / Rotate / Logout)         Stamps SecurityContextHolder (ThreadLocal)
```

---

## 🔌 API Endpoints

| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :---: | :--- |
| `POST` | `/api/auth/register` | ❌ | Registers a new user with a BCrypt-hashed password |
| `POST` | `/api/auth/login` | ❌ | Returns short-lived `accessToken` in body & sets `HttpOnly` `refresh_token` cookie |
| `POST` | `/api/auth/refresh-token` | Cookie | Revokes old refresh token and issues a rotated Access + Refresh token pair |
| `POST` | `/api/auth/logout` | Cookie | Revokes active refresh token in DB and clears the browser cookie (`Max-Age=0`) |
| `GET` | `/api/users/me` | Bearer JWT | Protected test endpoint returning claims extracted from the stateless JWT |

---

## ⚡ Quick Start

### 1. Start PostgreSQL via Docker
```bash
docker-compose up -d
```
*(Spins up PostgreSQL on host port `5433` mapped to container port `5432`)*

### 2. Run the Application
```bash
./mvnw spring-boot:run
```
*(Flyway automatically executes `V1__init_auth_schema.sql` and starts the server on `http://localhost:8081`)*

---

## 📁 Project Structure

```text
src/main/java/com/zev/identity_guard/
├── config/          # SecurityFilterChain & BCrypt PasswordEncoder beans
├── controller/      # Auth endpoints (HttpOnly cookie handling) & protected test routes
├── dto/             # Java 21 immutable records for requests & responses
├── entity/          # JPA entities (AppUser, RefreshToken)
├── repository/      # Spring Data JPA repositories
├── security/        # JwtService (JJWT) & OncePerRequestFilter implementation
└── service/         # Registration, login, token rotation & revocation logic
```
