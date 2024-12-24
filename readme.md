# Secure AI Agent Wallet with Human MFA Confirmation

This project provides a secure, headless wallet framework designed for AI agents with a crucial human oversight feature: Multi-Factor Authentication (MFA) confirmation for all transactions. This ensures that no transaction is executed without explicit approval from a human user.

## Architecture

The system comprises a backend (Flask) and a frontend (e.g., React) that interact through a secure API.  AI agents use API keys for authentication, while users utilize JWTs (JSON Web Tokens) and MFA for authorization and transaction confirmation. Private keys are managed and encrypted solely on the backend.

## Security Features

* **API Key Authentication (for AI Agents):** Each AI agent is assigned a unique API key for authentication and authorization.
* **JWT (JSON Web Tokens) (for Users):**  Users authenticate with username/password and are issued JWTs for secure access to the API.
* **MFA (Multi-Factor Authentication):** Users are required to set up MFA using TOTP (Time-based One-Time Passwords), adding a layer of security for transaction authorization. MFA secrets are encrypted at rest.
* **Backend Key Management:** Private keys are never exposed to the frontend. They are encrypted at rest using Fernet, with PBKDF2HMAC for key derivation.  Future enhancements may include HSMs or MPC for stronger security.
* **Transaction Authorization Flow:** AI agents prepare transactions, but users must explicitly authorize them via MFA before execution.  This prevents unauthorized agent activity.

## Frontend Integration

Frontend applications interact with the backend API using standard HTTP requests, including API keys (for agents) or JWTs (for users) in the `Authorization` header.

## API Endpoints

| Endpoint                 | Method | Description                                                       | Authentication                                       |
|--------------------------|--------|-------------------------------------------------------------------|----------------------------------------------------|
| `/api/register`          | POST   | Registers a new user.                                             | None                                               |
| `/api/login`             | POST   | User login; returns a JWT.                                        | None                                               |
| `/api/create_wallet`      | POST   | Creates a new wallet for the authenticated user.                 | JWT, User Password                                |
| `/api/load_wallet`       | POST   | Loads a user's wallet (agent or user).                       | JWT, Password, MFA Code, Wallet Address (if User)  |   
| `/api/setup_mfa`         | POST   | Sets up/overwrites MFA.                                           | JWT                                             |
| `/api/prepare_transaction` | POST   | Agent prepares a transaction (requires authorization).            | API Key, User ID                               |
| `/api/authorize_transaction` | POST | User authorizes a pending transaction with MFA.                   | JWT, MFA Code, Transaction ID                   |
| `/api/transaction_status` | GET    | Agent retrieves a pending transaction's status.                   | API Key, Transaction ID                          |
| `/api/execute_transaction` | POST   | Agent executes an authorized transaction.                        | API Key, Transaction ID                          |
| `/api/transfer`          | POST   | User-initiated native token transfer.                             | JWT, Password, MFA Code, To Address, Amount, Wallet Address |
| `/api/transfer_erc20`     | POST   | User-initiated ERC20 token transfer.                              | JWT, Password, MFA Code, Token Address, To Address, Amount, Wallet Address |
| `/api/contract_call`     | POST   | User-initiated smart contract interaction.                         | JWT, Password, MFA Code, Contract Details, Wallet Address |


## User Flow

1. **Registration & Wallet Creation:** User registers (`/api/register`), creates a wallet (`/api/create_wallet`), and sets up MFA (`/api/setup_mfa`).

2. **Agent Wallet Loading & Transaction Preparation:**  Agent authenticates (using API Key), loads the wallet (`/api/load_wallet`), and prepares a transaction (`/api/prepare_transaction`).

3. **User Authorization:** User receives a notification, reviews the transaction, and authorizes it with MFA (`/api/authorize_transaction`).

4. **Agent Transaction Execution:** Agent polls (`/api/transaction_status`) or receives a notification (WebSockets), then executes the authorized transaction (`/api/execute_transaction`).


## Transaction Flow Diagram

```mermaid sequenceDiagram
    participant Agent    participant Backend    participant Database    participant User    participant Blockchain     Agent->>+Backend: prepare_transaction (API Key, tx details, username)    Backend->>+Database: Store pending transaction (tx_id, details, etc.)    Database-->>-Backend: transaction_id (UUID)    Backend-->>-Agent: transaction_id (202 Accepted)     Backend->>User: Notification (tx details, transaction_id)     User->>+Backend: authorize_transaction (JWT, MFA code, transaction_id)    Backend->>+Database: Verify MFA & update tx status to 'authorized'    Database-->>-Backend: Success/Failure    Backend-->>-User: Authorization result (200 OK/Error)     Agent->>+Backend: transaction_status (API Key, transaction_id)    Backend->>+Database: Retrieve transaction status    Database-->>-Backend: Transaction Status (authorized/pending/rejected)    Backend-->>-Agent: Transaction Status     Agent->>+Backend: execute_transaction (API Key, transaction_id)    Backend->>+Database: Retrieve authorized transaction details    Database-->>-Backend: Transaction details    Backend->>+Blockchain: Execute transaction    Blockchain-->>-Backend: tx_hash    Backend-->>-Agent: tx_hash (201 Created) 
```

## Prerequisites

1.  **Python 3.9+:** Check with `python3 --version`.
2.  **Virtual Environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # macOS/Linux
    .venv\Scripts\activate     # Windows
    ```
3.  **Dependencies:** `pip install -r requirements.txt`
4.  **PostgreSQL:** Install locally and create a database and user, or use Cloud SQL (recommended for production).
5.  **Cloud SQL Auth Proxy (If using Cloud SQL):** Install, authenticate (`gcloud auth login` or `gcloud auth application-default login`), and start: `cloud_sql_proxy -instances=<YOUR_INSTANCE_CONNECTION_NAME>=tcp:5432 &` (or `tcp:0` and update `.env`).
6.  **Environment Variables:** Create a `.env` file (see `.env.example`):
    ```
    GOOGLE_API_KEY="..."    
    API_SECRET="..."       
    JWT_SECRET_KEY="..."   
    JWT_ACCESS_TOKEN_EXPIRES=...
    DATABASE_URL="..."
    WEB3_PROVIDER_URI="..." # Your web3 provider, for example infura, alchemy or ganache, for testing.     
    ```
    * **`DATABASE_URL` examples:**
       * Local: `postgresql://user:password@host:port/database`
       * Cloud SQL (proxy): `postgresql://user:password@127.0.0.1:<PORT>/database?sslmode=disable` (Replace placeholders. `<PORT>` is `5432` unless using `tcp:0`, then it's the proxy-assigned port).


7.  **Database Migrations:**
    * Create the `migrations/versions` directory.
    * Add SQL migration scripts (e.g., `001_create_users.sql`, `002_create_wallets.sql`, `003_add_mfa_secret_to_users.sql`). Down migrations (for rollback) are not implemented but recommended.
    * Run: `python app.py` (migrations applied on startup).
    * Create a test user (psql or implement `/api/register`) and log in to get a JWT for testing other endpoints.
    * Create an API key for your AI agent. This can be stored in the database, for example in a table called `api_keys`.  Store the API keys securely, and consider hashing or encrypting.  You will also need to implement logic for validating API keys when the agent makes a request. The request headers should include `X-API-KEY` and the key itself.  You can use this key to authenticate the agent.



## Database Migrations

Schema changes are managed with versioned scripts in `migrations/versions`.  `apply_migrations` applies new migrations on startup.

## Development and Deployment

* **Local Development:**  PostgreSQL and optionally Cloud SQL Auth proxy if using Cloud SQL.
* **Production:** Cloud SQL (PostgreSQL) is recommended.

## Security Best Practices

* **HTTPS (Production):** Essential.
* **Input Validation:** Validate all inputs.
* **Secure Coding:** Adhere to secure coding guidelines.
* **Secrets Management:** Use a secrets management service like Google Cloud Secret Manager or HashiCorp Vault in production for storing API keys, JWT secrets, and encryption keys.
* **Security Audits:** Regularly perform security audits and penetration testing.


## Future Enhancements

* **HSM Integration:** Improve key management security.
* **MPC Implementation:** Enhanced key security.
* **Frontend SDK:**  Simplified frontend integration.

