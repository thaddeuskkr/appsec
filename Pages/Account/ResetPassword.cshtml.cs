using System.ComponentModel.DataAnnotations;
using System.Text;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Pages.Account;

[AllowAnonymous]
public class ResetPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPasswordPolicyService _passwordPolicyService;
    private readonly IAuditLogService _auditLogService;
    private readonly SecurityPolicyOptions _policyOptions;

    public ResetPasswordModel(
        UserManager<ApplicationUser> userManager,
        IPasswordPolicyService passwordPolicyService,
        IAuditLogService auditLogService,
        IOptions<SecurityPolicyOptions> policyOptions)
    {
        _userManager = userManager;
        _passwordPolicyService = passwordPolicyService;
        _auditLogService = auditLogService;
        _policyOptions = policyOptions.Value;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public int PasswordMinLength => _policyOptions.PasswordMinLength;

    public bool RequireUppercase => _policyOptions.RequireUppercase;

    public bool RequireLowercase => _policyOptions.RequireLowercase;

    public bool RequireDigit => _policyOptions.RequireDigit;

    public bool RequireSpecial => _policyOptions.RequireSpecial;

    public IActionResult OnGet(string? code = null, string? email = null)
    {
        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(email))
        {
            return RedirectToPage("/Account/Login");
        }

        Input = new InputModel
        {
            Code = code,
            Email = email
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        Input.Email = NormalizeEmail(Input.Email);

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user is null)
        {
            TempData["StatusMessage"] = "Password has been reset.";
            return RedirectToPage("/Account/Login");
        }

        if (await _passwordPolicyService.IsPasswordReusedAsync(user, Input.Password, cancellationToken))
        {
            ModelState.AddModelError($"{nameof(Input)}.{nameof(InputModel.Password)}", "You cannot reuse your current or recent passwords.");
            return Page();
        }

        string resetToken;
        try
        {
            var decoded = WebEncoders.Base64UrlDecode(Input.Code);
            resetToken = Encoding.UTF8.GetString(decoded);
        }
        catch (FormatException)
        {
            ModelState.AddModelError(string.Empty, "Invalid reset token.");
            return Page();
        }

        var result = await _userManager.ResetPasswordAsync(user, resetToken, Input.Password);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await _auditLogService.LogAsync("ResetPassword", "Failed", user.Id, "Reset password failed.", cancellationToken);
            return Page();
        }

        _passwordPolicyService.MarkPasswordChanged(user);
        await _userManager.UpdateAsync(user);

        if (!string.IsNullOrWhiteSpace(user.PasswordHash))
        {
            await _passwordPolicyService.RecordPasswordHashAsync(user.Id, user.PasswordHash, cancellationToken);
        }

        await _auditLogService.LogAsync("ResetPassword", "Succeeded", user.Id, "Password reset succeeded.", cancellationToken);
        TempData["StatusMessage"] = "Password has been reset. Please login.";
        return RedirectToPage("/Account/Login");
    }

    private static string NormalizeEmail(string email)
    {
        return email.Trim();
    }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        [Display(Name = "Confirm password")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        public string Code { get; set; } = string.Empty;
    }
}
