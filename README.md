# Bookworms Online (Secure Membership App)

This project is an ASP.NET Core Razor Pages web app implementing security-focused registration and authentication features for an application security assignment.

## Implemented Security Features

- Registration with required profile fields and JPG photo upload validation.
- Strong password policy (client feedback + server enforcement).
- Unique email enforcement.
- Password hashing via ASP.NET Core Identity.
- Sensitive data encryption at rest (credit card, mobile, billing/shipping addresses).
- Secure login and logout flows.
- Google reCAPTCHA v3 verification on registration and login.
- Email OTP-based 2FA.
- Session management with timeout and single active session enforcement.
- Lockout after failed login attempts with automatic unlock.
- Password policy controls: min age, max age, history (reuse prevention).
- Forgot/reset password via SMTP email links.
- CSRF protection, Razor output encoding, and input validation.
- Custom 403, 404, and 500 error pages.
- Audit logging for critical security actions.
- GitHub CodeQL + Dependabot configuration.

## Prerequisites

- .NET SDK 10
- MariaDB server (external)
- Google reCAPTCHA v3 site and secret keys
- SMTP credentials for sending OTP and reset links

## Configuration

Update these files:

- `appsettings.json` (default values)
- `appsettings.Development.json` (demo-friendly overrides)

Important sections:

- `ConnectionStrings:DefaultConnection`
- `SecurityPolicy:*` (all timing/threshold controls)
- `Recaptcha:*`
- `Smtp:*`
- `Storage:*`

## Security Policy Tuning for Demo

You can change password age, lockout, and session settings directly in `appsettings.Development.json`.

After editing settings, restart the app for changes to take effect.

## Database Setup

1. Ensure your MariaDB database exists.
2. Set `ConnectionStrings:DefaultConnection`.
3. Apply migrations:

```bash
dotnet ef database update
```

## Run

```bash
dotnet restore
dotnet build
dotnet run
```

## Main Pages

- `/Account/Register`
- `/Account/Login`
- `/Account/Verify2fa`
- `/Account/ForgotPassword`
- `/Account/ResetPassword`
- `/Account/ChangePassword`
- `/` (authenticated member homepage)

## Notes

- Profile photos are stored outside `wwwroot` and served through an authorized endpoint.
- Credit card data is decrypted server-side but displayed masked on homepage.
- Do not commit real SMTP/reCAPTCHA/database secrets to source control.
