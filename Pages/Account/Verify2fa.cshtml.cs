using System.ComponentModel.DataAnnotations;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages.Account;

[AllowAnonymous]
public class Verify2faModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogService _auditLogService;
    private readonly IPasswordPolicyService _passwordPolicyService;
    private readonly IActiveSessionService _activeSessionService;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<Verify2faModel> _logger;

    public Verify2faModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditLogService auditLogService,
        IPasswordPolicyService passwordPolicyService,
        IActiveSessionService activeSessionService,
        IWebHostEnvironment environment,
        ILogger<Verify2faModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditLogService = auditLogService;
        _passwordPolicyService = passwordPolicyService;
        _activeSessionService = activeSessionService;
        _environment = environment;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string ReturnUrl { get; set; } = "/";

    [BindProperty(SupportsGet = true)]
    public bool RememberMe { get; set; }

    public void OnGet()
    {
        ReturnUrl = NormalizeReturnUrl(ReturnUrl);
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        ReturnUrl = NormalizeReturnUrl(ReturnUrl);

        if (!ModelState.IsValid)
        {
            var validationDetails = string.Join(
                " | ",
                ModelState
                    .Where(x => x.Value?.Errors.Count > 0)
                    .SelectMany(x => x.Value!.Errors.Select(error => $"{x.Key}: {error.ErrorMessage}")));

            if (string.IsNullOrWhiteSpace(validationDetails))
            {
                validationDetails = "Unknown model validation issue.";
            }

            _logger.LogWarning(
                "Two-factor validation failed before sign-in. Errors: {Errors}; ReturnUrl: {ReturnUrl}; RememberMe: {RememberMe}",
                validationDetails,
                ReturnUrl,
                RememberMe);

            await _auditLogService.LogAsync(
                "TwoFactor",
                "ModelInvalid",
                details: $"Model validation failed. {validationDetails}",
                cancellationToken: cancellationToken);

            ModelState.AddModelError(string.Empty, "Verification request is invalid. Please check the form and try again.");
            if (_environment.IsDevelopment())
            {
                ModelState.AddModelError(string.Empty, $"Debug details: {validationDetails}");
            }

            return Page();
        }

        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user is null)
        {
            _logger.LogWarning("Two-factor verification context missing. Redirecting to login.");
            await _auditLogService.LogAsync(
                "TwoFactor",
                "ContextMissing",
                details: "Two-factor user context was missing or expired.",
                cancellationToken: cancellationToken);

            TempData["ErrorMessage"] = "Two-factor verification expired. Please sign in again.";
            return RedirectToPage("/Account/Login");
        }

        var authenticatorCode = Input.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
        _logger.LogInformation(
            "Processing two-factor verification for user {UserId}. CodeLength={CodeLength}, RememberMe={RememberMe}.",
            user.Id,
            authenticatorCode.Length,
            RememberMe);

        var result = await _signInManager.TwoFactorSignInAsync(
            TokenOptions.DefaultEmailProvider,
            authenticatorCode,
            RememberMe,
            rememberClient: false);

        _logger.LogInformation(
            "Two-factor verification result for user {UserId}: Succeeded={Succeeded}, LockedOut={LockedOut}, NotAllowed={NotAllowed}, RequiresTwoFactor={RequiresTwoFactor}.",
            user.Id,
            result.Succeeded,
            result.IsLockedOut,
            result.IsNotAllowed,
            result.RequiresTwoFactor);

        if (result.Succeeded)
        {
            await _userManager.ResetAccessFailedCountAsync(user);
            var previousSessionToken = user.CurrentSessionToken;
            user.CurrentSessionToken = Guid.NewGuid().ToString("N");

            if (_passwordPolicyService.IsPasswordExpired(user))
            {
                user.ForcePasswordChange = true;
            }

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                var updateErrors = string.Join(", ", updateResult.Errors.Select(x => x.Description));
                _logger.LogError("Failed to persist session token for user {UserId}: {Errors}", user.Id, updateErrors);
                await _auditLogService.LogAsync(
                    "TwoFactor",
                    "Failed",
                    user.Id,
                    $"Failed to persist session token after 2FA. {updateErrors}",
                    cancellationToken);

                ModelState.AddModelError(string.Empty, "Login state could not be established. Please try signing in again.");
                return Page();
            }

            if (!string.IsNullOrWhiteSpace(previousSessionToken) &&
                !string.Equals(previousSessionToken, user.CurrentSessionToken, StringComparison.Ordinal))
            {
                await _activeSessionService.EndSessionAsync(previousSessionToken, cancellationToken);
            }

            await _activeSessionService.StartSessionAsync(user.Id, user.CurrentSessionToken, cancellationToken);

            // Re-issue the application cookie with the freshly persisted session token claim.
            await _signInManager.SignInAsync(user, isPersistent: RememberMe);
            await _auditLogService.LogAsync("TwoFactor", "Succeeded", user.Id, $"2FA validation successful. ReturnUrl={ReturnUrl}", cancellationToken);

            if (user.ForcePasswordChange)
            {
                return RedirectToPage("/Account/ChangePassword", new { expired = true });
            }

            return LocalRedirect(ReturnUrl);
        }

        if (result.IsLockedOut)
        {
            await _auditLogService.LogAsync("TwoFactor", "LockedOut", user.Id, "User locked during 2FA.", cancellationToken);
            TempData["ErrorMessage"] = "Too many invalid codes. Your account is temporarily locked.";
            return RedirectToPage("/Account/Login");
        }

        _logger.LogWarning("Two-factor verification failed for user {UserId}.", user.Id);
        await _auditLogService.LogAsync(
            "TwoFactor",
            "Failed",
            user.Id,
            "Invalid OTP code submitted.",
            cancellationToken);

        ModelState.AddModelError(string.Empty, "Invalid verification code. Please re-enter the latest code from your email.");
        if (_environment.IsDevelopment())
        {
            ModelState.AddModelError(
                string.Empty,
                $"Debug details: Succeeded={result.Succeeded}, LockedOut={result.IsLockedOut}, NotAllowed={result.IsNotAllowed}, RequiresTwoFactor={result.RequiresTwoFactor}");
        }

        return Page();
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
        [Display(Name = "Verification Code")]
        public string Code { get; set; } = string.Empty;
    }
}
