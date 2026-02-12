using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using BookwormsOnline.Services;
using BookwormsOnline.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

[AllowAnonymous]
public class RegisterModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IFieldEncryptionService _encryptionService;
    private readonly IPhotoStorageService _photoStorageService;
    private readonly IRecaptchaService _recaptchaService;
    private readonly IAuditLogService _auditLogService;
    private readonly IPasswordPolicyService _passwordPolicyService;
    private readonly IEmailSender _emailSender;
    private readonly SecurityPolicyOptions _securityPolicy;
    private readonly RecaptchaOptions _recaptchaOptions;

    public RegisterModel(
        UserManager<ApplicationUser> userManager,
        IFieldEncryptionService encryptionService,
        IPhotoStorageService photoStorageService,
        IRecaptchaService recaptchaService,
        IAuditLogService auditLogService,
        IPasswordPolicyService passwordPolicyService,
        IEmailSender emailSender,
        IOptions<SecurityPolicyOptions> securityPolicy,
        IOptions<RecaptchaOptions> recaptchaOptions)
    {
        _userManager = userManager;
        _encryptionService = encryptionService;
        _photoStorageService = photoStorageService;
        _recaptchaService = recaptchaService;
        _auditLogService = auditLogService;
        _passwordPolicyService = passwordPolicyService;
        _emailSender = emailSender;
        _securityPolicy = securityPolicy.Value;
        _recaptchaOptions = recaptchaOptions.Value;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string RecaptchaSiteKey => _recaptchaOptions.SiteKey;

    public int PasswordMinLength => _securityPolicy.PasswordMinLength;

    public bool RequireUppercase => _securityPolicy.RequireUppercase;

    public bool RequireLowercase => _securityPolicy.RequireLowercase;

    public bool RequireDigit => _securityPolicy.RequireDigit;

    public bool RequireSpecial => _securityPolicy.RequireSpecial;

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        Input.Email = NormalizeEmail(Input.Email);
        await ValidateRecaptchaAsync(cancellationToken);
        ValidatePasswordComplexity(Input.Password);

        if (Input.Photo is null)
        {
            ModelState.AddModelError($"{nameof(Input)}.{nameof(InputModel.Photo)}", "Photo upload is required.");
        }

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var existingUser = await _userManager.FindByEmailAsync(Input.Email);
        if (existingUser is not null)
        {
            ModelState.AddModelError($"{nameof(Input)}.{nameof(InputModel.Email)}", "An account with this email already exists.");
            return Page();
        }

        string? photoFileName = null;
        try
        {
            photoFileName = await _photoStorageService.SavePhotoAsync(Input.Photo!, cancellationToken);
        }
        catch (Exception exception)
        {
            ModelState.AddModelError($"{nameof(Input)}.{nameof(InputModel.Photo)}", exception.Message);
            return Page();
        }

        var user = new ApplicationUser
        {
            UserName = Input.Email,
            Email = Input.Email,
            EmailConfirmed = false,
            FirstName = Input.FirstName.Trim(),
            LastName = Input.LastName.Trim(),
            PhoneNumber = Input.MobileNo.Trim(),
            EncryptedCreditCard = _encryptionService.Encrypt(NormalizeCard(Input.CreditCardNo)),
            EncryptedMobileNo = _encryptionService.Encrypt(Input.MobileNo.Trim()),
            EncryptedBillingAddress = _encryptionService.Encrypt(Input.BillingAddress.Trim()),
            EncryptedShippingAddress = _encryptionService.Encrypt(Input.ShippingAddress.Trim()),
            PhotoFileName = photoFileName,
            TwoFactorEnabled = Input.EnableTwoFactor
        };

        _passwordPolicyService.MarkPasswordChanged(user);

        var createResult = await _userManager.CreateAsync(user, Input.Password);
        if (!createResult.Succeeded)
        {
            var hasDuplicateEmailError = false;
            foreach (var error in createResult.Errors)
            {
                if (error.Code.Contains("DuplicateEmail", StringComparison.OrdinalIgnoreCase) ||
                    error.Code.Contains("DuplicateUserName", StringComparison.OrdinalIgnoreCase))
                {
                    hasDuplicateEmailError = true;
                    continue;
                }

                ModelState.AddModelError(string.Empty, error.Description);
            }

            if (hasDuplicateEmailError)
            {
                ModelState.AddModelError($"{nameof(Input)}.{nameof(InputModel.Email)}", "An account with this email already exists.");
            }

            if (!string.IsNullOrWhiteSpace(photoFileName))
            {
                await _photoStorageService.DeleteIfExistsAsync(photoFileName, cancellationToken);
            }

            await _auditLogService.LogAsync("Register", "Failed", details: "Identity user creation failed.", cancellationToken: cancellationToken);
            return Page();
        }

        if (!string.IsNullOrWhiteSpace(user.PasswordHash))
        {
            await _passwordPolicyService.RecordPasswordHashAsync(user.Id, user.PasswordHash, cancellationToken);
        }

        await _auditLogService.LogAsync("Register", "Succeeded", user.Id, "New member account registered.", cancellationToken);

        var confirmationSent = await SendEmailConfirmationLinkAsync(user, cancellationToken);
        if (!confirmationSent)
        {
            TempData["ErrorMessage"] = "Registration completed, but we could not send your confirmation email. You can request another link.";
            return RedirectToPage("/Account/ResendConfirmation", new { email = user.Email });
        }

        TempData["StatusMessage"] = "Registration successful. Please verify your email before signing in.";
        return RedirectToPage("/Account/Login");
    }

    private async Task<bool> SendEmailConfirmationLinkAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var callbackUrl = Url.Page(
            "/Account/ConfirmEmail",
            pageHandler: null,
            values: new { userId = user.Id, code = encodedToken },
            protocol: Request.Scheme);

        if (string.IsNullOrWhiteSpace(callbackUrl))
        {
            await _auditLogService.LogAsync(
                "EmailConfirmation",
                "Failed",
                user.Id,
                "Email confirmation callback URL generation failed.",
                cancellationToken);
            return false;
        }

        try
        {
            await _emailSender.SendAsync(
                user.Email!,
                "Confirm your Bookworms Online account",
                $"<p>Please confirm your email by <a href=\"{HtmlEncoder.Default.Encode(callbackUrl)}\">clicking this link</a>.</p>",
                cancellationToken);
            await _auditLogService.LogAsync(
                "EmailConfirmation",
                "Sent",
                user.Id,
                "Confirmation email sent after registration.",
                cancellationToken);
            return true;
        }
        catch (Exception exception)
        {
            await _auditLogService.LogAsync(
                "EmailConfirmation",
                "Failed",
                user.Id,
                $"Confirmation email sending failed. {exception.GetType().Name}",
                cancellationToken);
            return false;
        }
    }

    private async Task ValidateRecaptchaAsync(CancellationToken cancellationToken)
    {
        var verification = await _recaptchaService.VerifyAsync(
            Input.RecaptchaToken,
            "register",
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);

        if (!verification.Success)
        {
            ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
        }
    }

    private void ValidatePasswordComplexity(string password)
    {
        var issues = new List<string>();

        if (password.Length < _securityPolicy.PasswordMinLength)
        {
            issues.Add($"at least {_securityPolicy.PasswordMinLength} characters");
        }

        if (_securityPolicy.RequireUppercase && !password.Any(char.IsUpper))
        {
            issues.Add("an uppercase letter");
        }

        if (_securityPolicy.RequireLowercase && !password.Any(char.IsLower))
        {
            issues.Add("a lowercase letter");
        }

        if (_securityPolicy.RequireDigit && !password.Any(char.IsDigit))
        {
            issues.Add("a number");
        }

        if (_securityPolicy.RequireSpecial && password.All(char.IsLetterOrDigit))
        {
            issues.Add("a special character");
        }

        if (issues.Count > 0)
        {
            ModelState.AddModelError($"{nameof(Input)}.{nameof(InputModel.Password)}", $"Password must contain {string.Join(", ", issues)}.");
        }
    }

    private static string NormalizeCard(string cardInput)
    {
        return new string(cardInput.Where(char.IsDigit).ToArray());
    }

    private static string NormalizeEmail(string email)
    {
        return email.Trim();
    }

    public class InputModel
    {
        [Required]
        [StringLength(100)]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Credit Card Number")]
        [RegularExpression(@"^[0-9\s-]+$", ErrorMessage = "Credit card can only contain digits, spaces, and dashes.")]
        [Luhn]
        public string CreditCardNo { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Mobile Number")]
        [Phone]
        [RegularExpression(@"^\+?[0-9\-\s]{8,20}$", ErrorMessage = "Enter a valid mobile number.")]
        public string MobileNo { get; set; } = string.Empty;

        [Required]
        [StringLength(250)]
        [Display(Name = "Billing Address")]
        public string BillingAddress { get; set; } = string.Empty;

        [Required]
        [StringLength(250)]
        [Display(Name = "Shipping Address")]
        public string ShippingAddress { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match.")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Display(Name = "Enable Two-Factor Authentication (Email OTP)")]
        public bool EnableTwoFactor { get; set; } = true;

        [Required]
        [Display(Name = "Photo (.JPG only)")]
        public IFormFile? Photo { get; set; }

        public string RecaptchaToken { get; set; } = string.Empty;
    }
}
