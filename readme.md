# Secure Headless Wallet Framework

This framework provides a secure, headless wallet solution designed for integration with frontend applications. It prioritizes security by handling sensitive operations on the backend and leveraging API keys, JWT (JSON Web Tokens), and MFA (Multi-Factor Authentication).

## Architecture

The framework employs a backend service (e.g., Flask) that manages wallet creation, balance retrieval, transaction processing, and other sensitive actions. Frontend applications (e.g., React) interact with this backend through secure API calls.

## Security Features

* **API Keys:** Used for initial authentication and identification of the frontend application.
* **JWT (JSON Web Tokens):**  Provides secure authentication and authorization for individual users. JWTs are issued upon successful login and used for subsequent API calls.
* **MFA (Multi-Factor Authentication):** Adds an extra layer of security for critical operations like transaction signing.  This implementation uses TOTP (Time-based One-Time Passwords), compatible with Google Authenticator and similar apps.
* **Backend Key Management:** Private keys are handled exclusively on the backend, never exposed to the frontend.  Encryption at rest is employed, and more advanced solutions like hardware security modules (HSMs) or multi-party computation (MPC) can be integrated for enhanced security.

## Frontend Integration

Frontend applications interact with the backend API using standard HTTP requests.  API keys and JWTs are included in request headers for authentication and authorization.  The framework is designed to be compatible with various frontend technologies, such as React.

## API Endpoints


| Endpoint          | Method | Description                                           | Authentication        |
|-------------------|--------|-------------------------------------------------------|-----------------------|
| `/api/register`   | POST   | Registers a new user.                               | None                  |
| `/api/login`      | POST   | Logs in a user and returns a JWT.                    | None                  |
| `/api/create_wallet` | POST   | Creates a new wallet for the authenticated user.     | JWT, User Password    |
| `/api/setup_mfa`  | POST   | Sets up or overwrites MFA for the authenticated user. | JWT                   |
|  *(Other wallet operations endpoints)* |  GET/POST etc.  | e.g., get balance, send transaction, etc. | JWT, potentially MFA |


## Prerequisites

Before running the application, ensure you have the following set up:

1. **Python 3.9 (or compatible):** This project is developed using Python 3.9. You can check your Python version with `python3 --version`.

2. **Virtual Environment (Recommended):** It's highly recommended to use a virtual environment to isolate project dependencies.

   ```bash
   python3 -m venv .venv  # Create a virtual environment
   source .venv/bin/activate  # Activate the environment (macOS/Linux)
   .venv\Scripts\activate # Activate the environment (Windows)
   pip install -r requirements.txt

3. **Cloud SQL (Recommended for Production):** Create a Cloud SQL PostgreSQL instance in the Google Cloud Console. Crucially, 	configure Private IP connectivity. You'll use the Cloud SQL Auth Proxy for secure access.
4. **Cloud SQL Auth Proxy (Required for Cloud SQL):**
Download and Install: Download and install the Cloud SQL Auth Proxy from the Google Cloud website. Choose the appropriate 	package for your operating system.
​Authentication: Authenticate with Google Cloud. The easiest way is using the gcloud command-line tool. If you haven't already, 	install the Google Cloud SDK and run gcloud auth login. If the proxy is having issues connecting, and you have already authorized your local machine's IP address to connect to the instance, try running gcloud auth application-default login which sometimes resolves obscure authentication issues. This generates credentials in a slightly different way.
Start the Proxy: Run the proxy. If using tcp:0 ensure that you are also using the selected port in your .env file DATABASE_URL.
```bash 
cloud_sql_proxy -instances=<PROJECT-ID>:<REGION>:<INSTANCE-NAME>=tcp:<PORT> &
```
Replace <PROJECT_ID>:<REGION>:<INSTANCE_NAME> with your Cloud SQL instance connection name. This value can be found in the Cloud SQL instances page in the Google Cloud Console.
If connecting directly with psql you will usually want to use port 5432:
```bash cloud_sql_proxy -instances=<PROJECT-ID>:<REGION>:<INSTANCE_NAME>=tcp:5432 &
If connecting through your python application it is often easier to let the proxy choose a port for you in case something is already running on port 5432:
cloud_sql_proxy -instances=<PROJECT-ID>:<REGION>:<INSTANCE_NAME>=tcp:0 &
```
The proxy will select a random available port. You must use this port when setting up your DATABASE_URL environment variable, as described below. The proxy will output the selected port, for example:

Listening on 127.0.0.1:44915 for <YOUR_INSTANCE_CONNECTION_NAME>
Proxy initialized in 796.66411ms

5. Environment Variables (.env file):

#... other env variables
DATABASE_URL="postgresql://<username>:<password>@127.0.0.1:<PORT>/<database_name>?sslmode=disable"
Replace <username>, <password>, and <database_name> with your Cloud SQL database credentials. Replace <PORT> with 5432 or the port printed by the proxy if you are using the tcp:0 argument with the proxy.



## Database Migrations
Database schema migrations are managed using SQL scripts located in the `migrations/versions` directory.  The `apply_migrations` function in the backend code automatically applies new migrations upon application startup. Each migration file is versioned numerically, allowing only new schema changes to be applied.



## Development and Deployment

* **Local Development:** For local development, PostgreSQL is used.  The Cloud SQL Auth proxy is used for secure connections to Cloud SQL instances during development.
* **Production:**  Cloud SQL (PostgreSQL) is recommended for production due to its security features, scalability, and managed services.



## Security Best Practices

* **HTTPS:**  Always use HTTPS in production to secure communication between the frontend and backend.
* **Input Validation:** Validate all user inputs thoroughly to prevent vulnerabilities.
* **Secure Coding Practices:** Follow secure coding guidelines to minimize vulnerabilities.
* **Regular Security Audits:**  Perform regular security audits and penetration testing.

## Future Enhancements

* **HSM Integration:** Integrate with a Hardware Security Module (HSM) for more robust key management.
* **MPC Implementation:** Implement Multi-Party Computation (MPC) for enhanced key security.
* **More Sophisticated Frontend Integration:** Include frontend libraries/SDKs for easier integration.

This updated README provides a more comprehensive overview of the secure headless wallet framework, its architecture, security features, API endpoints, and development/deployment considerations.  It highlights the key security aspects of the framework and emphasizes best practices for secure wallet management.
