# Security Checklist Mapping (Assignment Rubric)

## Registration Form
- [x] Save member info into database
- [x] Duplicate email detection and prevention

## Securing Credential (Password Complexity)
- [x] Minimum 12 characters (configurable)
- [x] Requires uppercase/lowercase/number/special (configurable)
- [x] Client-side feedback for strong password
- [x] Server-side password policy via Identity + custom checks

## Securing User Data and Passwords
- [x] Password hashing via ASP.NET Core Identity
- [x] Encryption at rest for sensitive customer data
- [x] Decryption for homepage display with masked credit card output

## Session Management
- [x] Secure authenticated session on successful login
- [x] Session idle timeout (configurable)
- [x] Redirect to login when session invalid/expired
- [x] Detect and block concurrent sessions (single active session mode)

## Login / Logout
- [x] Login works after successful registration
- [x] Lockout after configured failed login attempts
- [x] Safe logout clears session and token
- [x] Audit log for authentication events
- [x] Redirect to homepage after successful verification

## Anti-bot
- [x] Google reCAPTCHA v3 integrated in registration and login

## Proper Input Validation
- [x] Client + server validation on key inputs
- [x] CSRF protection on unsafe methods
- [x] XSS mitigation through Razor encoding
- [x] SQL injection mitigation through EF Core parameterization
- [x] Validation/error messages for invalid inputs

## Proper Error Handling
- [x] Custom 403/404/500 pages
- [x] Graceful production exception handling

## Software Testing / Source Code Analysis
- [x] GitHub CodeQL workflow
- [x] Dependabot config

## Advanced Features
- [x] Automatic account recovery after lockout period
- [x] Prevent password reuse (last 2 history)
- [x] Change password
- [x] Reset password via email link
- [x] Minimum/maximum password age policies
- [x] 2FA via email OTP
