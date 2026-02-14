# Web Application Security Checklist

## Registration and User Data Management

- [X] Implement successful saving of member info into the database
- [X] Check for duplicate email addresses and handle appropriately
- [X] Implement strong password requirements:
  - [X] Minimum 12 characters
  - [X] Combination of lowercase, uppercase, numbers, and special characters
  - [X] Provide feedback on password strength
  - [X] Implement both client-side and server-side password checks
- [X] Encrypt sensitive user data in the database (e.g., NRIC, credit card numbers)
- [X] Implement proper password hashing and storage
- [X] Implement file upload restrictions (e.g., .docx, .pdf, or .jpg only)

## Session Management

- [X] Create a secure session upon successful login
- [X] Implement session timeout
- [X] Route to homepage/login page after session timeout
- [X] Detect and handle multiple logins from different devices/browser tabs

## Login/Logout Security

- [X] Implement proper login functionality
- [X] Implement rate limiting (e.g., account lockout after 3 failed login attempts)
- [X] Perform proper and safe logout (clear session and redirect to login page)
- [X] Implement audit logging (save user activities in the database)
- [X] Redirect to homepage after successful login, displaying user info

## Anti-Bot Protection

- [X] Implement Google reCAPTCHA v3 service

## Input Validation and Sanitization

- [X] Prevent injection attacks (e.g., SQL injection)
- [X] Implement Cross-Site Request Forgery (CSRF) protection
- [X] Prevent Cross-Site Scripting (XSS) attacks
- [X] Perform proper input sanitization, validation, and verification for all user inputs
- [X] Implement both client-side and server-side input validation
- [X] Display error or warning messages for improper input
- [X] Perform proper encoding before saving data into the database

## Error Handling

- [X] Implement graceful error handling on all pages
- [X] Create and display custom error pages (e.g., 404, 403)

## Software Testing and Security Analysis

- [X] Perform source code analysis using external tools (e.g., GitHub)
- [X] Address security vulnerabilities identified in the source code

## Advanced Security Features

- [X] Implement automatic account recovery after lockout period
- [X] Enforce password history (avoid password reuse, max 2 password history)
- [X] Implement change password functionality
- [X] Implement reset password functionality (using email link or SMS)
- [X] Enforce minimum and maximum password age policies
- [X] Implement Two-Factor Authentication (2FA)

## General Security Best Practices

- [X] Use HTTPS for all communications
- [X] Implement proper access controls and authorization
- [X] Keep all software and dependencies up to date
- [X] Follow secure coding practices
- [X] Regularly backup and securely store user data
- [X] Implement logging and monitoring for security events

## Documentation and Reporting

- [X] Prepare a report on implemented security features
- [X] Complete and submit the security checklist

Remember to test each security feature thoroughly and ensure they work as expected in your web application.
