# 5-7 Minute Demo Script

## 1. Configuration (30-45s)
- Open `appsettings.Development.json`.
- Show configurable values:
  - `PasswordMinAgeMinutes`
  - `PasswordMaxAgeDays`
  - `LockoutMaxFailedAttempts`
  - `LockoutMinutes`
  - `SessionIdleTimeoutMinutes`
- Explain these can be edited for demo flow and applied on app restart.

## 2. Registration (60-90s)
- Open `/Account/Register`.
- Show required fields and JPG-only upload.
- Enter weak password to demonstrate feedback/validation.
- Submit valid data and register.
- Mention unique email check and reCAPTCHA verification.

## 3. Login + 2FA + Session (90-120s)
- Login with registered account.
- Receive OTP email and complete `/Account/Verify2fa`.
- Show homepage with profile info and masked credit card.
- Open another browser/device and login again to demonstrate previous session invalidation.

## 4. Lockout and Recovery (45-60s)
- Attempt wrong password repeatedly to trigger lockout.
- Show lockout message and explain automatic unlock timing from config.

## 5. Password Controls (60-90s)
- Navigate to `/Account/ChangePassword`.
- Demonstrate min-age restriction and password history reuse block.
- Demonstrate forgot/reset flow via email link.

## 6. Error Handling + Security Pipeline (30-45s)
- Visit a non-existing URL to show custom 404 page.
- Show `.github/workflows/codeql.yml` and `.github/dependabot.yml` in repository.
