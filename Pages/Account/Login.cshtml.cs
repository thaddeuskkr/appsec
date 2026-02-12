using System.ComponentModel.DataAnnotations;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

[AllowAnonymous]
public class LoginModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IRecaptchaService _recaptchaService;
    private readonly IAuditLogService _auditLogService;
    private readonly IEmailSender _emailSender;
    private readonly IPasswordPolicyService _passwordPolicyService;
    private readonly IActiveSessionService _activeSessionService;
    private readonly SecurityPolicyOptions _securityPolicyOptions;
    private readonly RecaptchaOptions _recaptchaOptions;

    public LoginModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IRecaptchaService recaptchaService,
        IAuditLogService auditLogService,
        IEmailSender emailSender,
        IPasswordPolicyService passwordPolicyService,
        IActiveSessionService activeSessionService,
        IOptions<SecurityPolicyOptions> securityPolicyOptions,
        IOptions<RecaptchaOptions> recaptchaOptions)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _recaptchaService = recaptchaService;
        _auditLogService = auditLogService;
        _emailSender = emailSender;
        _passwordPolicyService = passwordPolicyService;
        _activeSessionService = activeSessionService;
        _securityPolicyOptions = securityPolicyOptions.Value;
        _recaptchaOptions = recaptchaOptions.Value;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string RecaptchaSiteKey => _recaptchaOptions.SiteKey;

    public string? ReturnUrl { get; set; }

    public void OnGet(string? returnUrl = null)
    {
        ReturnUrl = NormalizeReturnUrl(returnUrl);
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null, CancellationToken cancellationToken = default)
    {
        Input.Email = NormalizeEmail(Input.Email);
        ReturnUrl = NormalizeReturnUrl(returnUrl);

        var recaptcha = await _recaptchaService.VerifyAsync(
            Input.RecaptchaToken,
            "login",
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);

        if (!recaptcha.Success)
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user is null)
        {
            await _auditLogService.LogAsync("Login", "Failed", details: "Unknown email.", cancellationToken: cancellationToken);
            ModelState.AddModelError(string.Empty, "Invalid username and/or password.");
            return Page();
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
            var minutes = lockoutEnd.HasValue
                ? Math.Max(1, (int)Math.Ceiling((lockoutEnd.Value - DateTimeOffset.UtcNow).TotalMinutes))
                : _securityPolicyOptions.LockoutMinutes;
            ModelState.AddModelError(string.Empty, $"Account is locked. Try again in about {minutes} minute(s).");
            await _auditLogService.LogAsync("Login", "LockedOut", user.Id, "Account currently locked.", cancellationToken);
            return Page();
        }

        var signInResult = await _signInManager.PasswordSignInAsync(user, Input.Password, Input.RememberMe, lockoutOnFailure: true);

        if (signInResult.RequiresTwoFactor)
        {
            var code = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            try
            {
                await _emailSender.SendAsync(
                    user.Email!,
                    "Bookworms Online verification code",
                    $"<p>Your login verification code is <strong>{code}</strong>.</p><p>If this was not you, ignore this email.</p>",
                    cancellationToken);
            }
            catch (Exception)
            {
                await _auditLogService.LogAsync("Login", "Failed", user.Id, "Could not send OTP email.", cancellationToken);
                ModelState.AddModelError(string.Empty, "Unable to send verification code right now. Please try again.");
                return Page();
            }

            await _auditLogService.LogAsync("Login", "TwoFactorPending", user.Id, "Password validated, OTP sent.", cancellationToken);

            return RedirectToPage("/Account/Verify2fa", new
            {
                ReturnUrl,
                Input.RememberMe
            });
        }

        if (signInResult.IsNotAllowed)
        {
            await _auditLogService.LogAsync("Login", "NotAllowed", user.Id, "Sign-in blocked because account is not confirmed.", cancellationToken);
            TempData["ErrorMessage"] = "Your email is not verified yet. Please confirm your email before signing in.";
            return RedirectToPage("/Account/ResendConfirmation", new { email = user.Email });
        }

        if (signInResult.Succeeded)
        {
            await _userManager.ResetAccessFailedCountAsync(user);
            var sessionUpdated = await RefreshSessionTokenAsync(user, Input.RememberMe, cancellationToken);
            if (!sessionUpdated)
            {
                await _auditLogService.LogAsync("Login", "Failed", user.Id, "Failed to establish session token.", cancellationToken);
                ModelState.AddModelError(string.Empty, "Could not establish login session. Please try again.");
                return Page();
            }

            await _auditLogService.LogAsync("Login", "Succeeded", user.Id, "Signed in without 2FA challenge.", cancellationToken);

            if (_passwordPolicyService.IsPasswordExpired(user))
            {
                user.ForcePasswordChange = true;
                await _userManager.UpdateAsync(user);
                return RedirectToPage("/Account/ChangePassword", new { expired = true });
            }

            return LocalRedirect(ReturnUrl ?? Url.Content("~/"));
        }

        if (signInResult.IsLockedOut)
        {
            await _auditLogService.LogAsync("Login", "LockedOut", user.Id, "User became locked after failures.", cancellationToken);
            ModelState.AddModelError(string.Empty, "Too many failed attempts. Your account is temporarily locked.");
            return Page();
        }

        await _auditLogService.LogAsync("Login", "Failed", user.Id, "Invalid credentials.", cancellationToken);
        ModelState.AddModelError(string.Empty, "Invalid username and/or password.");
        return Page();
    }

    private async Task<bool> RefreshSessionTokenAsync(ApplicationUser user, bool isPersistent, CancellationToken cancellationToken)
    {
        var previousSessionToken = user.CurrentSessionToken;
        user.CurrentSessionToken = Guid.NewGuid().ToString("N");
        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(previousSessionToken) &&
            !string.Equals(previousSessionToken, user.CurrentSessionToken, StringComparison.Ordinal))
        {
            await _activeSessionService.EndSessionAsync(previousSessionToken, cancellationToken);
        }

        await _activeSessionService.StartSessionAsync(user.Id, user.CurrentSessionToken, cancellationToken);
        await _signInManager.SignInAsync(user, isPersistent: isPersistent);
        return true;
    }

    private static string NormalizeEmail(string email)
    {
        return email.Trim();
    }

    private string NormalizeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl))
        {
            return Url.Content("~/");
        }

        return returnUrl;
    }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember Me")]
        public bool RememberMe { get; set; }

        public string RecaptchaToken { get; set; } = string.Empty;
    }
}
