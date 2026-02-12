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

[Authorize]
public class ChangePasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IPasswordPolicyService _passwordPolicyService;
    private readonly IAuditLogService _auditLogService;
    private readonly SecurityPolicyOptions _policyOptions;

    public ChangePasswordModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IPasswordPolicyService passwordPolicyService,
        IAuditLogService auditLogService,
        IOptions<SecurityPolicyOptions> policyOptions)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _passwordPolicyService = passwordPolicyService;
        _auditLogService = auditLogService;
        _policyOptions = policyOptions.Value;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool IsPasswordExpired { get; set; }

    public int PasswordMinAgeMinutes => _policyOptions.PasswordMinAgeMinutes;

    public async Task<IActionResult> OnGetAsync(bool expired = false)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Account/Login");
        }

        IsPasswordExpired = expired || _passwordPolicyService.IsPasswordExpired(user);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Account/Login");
        }

        IsPasswordExpired = _passwordPolicyService.IsPasswordExpired(user);

        if (!_passwordPolicyService.CanChangePassword(user, out var remaining) && !user.ForcePasswordChange)
        {
            ModelState.AddModelError(string.Empty, $"Password can only be changed after {Math.Ceiling(remaining.TotalMinutes)} more minute(s).");
            return Page();
        }

        if (await _passwordPolicyService.IsPasswordReusedAsync(user, Input.NewPassword, cancellationToken))
        {
            ModelState.AddModelError($"{nameof(Input)}.{nameof(InputModel.NewPassword)}", "You cannot reuse your current or recent passwords.");
            return Page();
        }

        var changeResult = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
        if (!changeResult.Succeeded)
        {
            foreach (var error in changeResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await _auditLogService.LogAsync("ChangePassword", "Failed", user.Id, "Password change failed.", cancellationToken);
            return Page();
        }

        _passwordPolicyService.MarkPasswordChanged(user);
        await _userManager.UpdateAsync(user);

        if (!string.IsNullOrWhiteSpace(user.PasswordHash))
        {
            await _passwordPolicyService.RecordPasswordHashAsync(user.Id, user.PasswordHash, cancellationToken);
        }

        await _signInManager.RefreshSignInAsync(user);
        await _auditLogService.LogAsync("ChangePassword", "Succeeded", user.Id, "Password updated.", cancellationToken);

        TempData["StatusMessage"] = "Your password has been changed.";
        return RedirectToPage("/Index");
    }

    public class InputModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current password")]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(NewPassword), ErrorMessage = "The new password and confirmation password do not match.")]
        [Display(Name = "Confirm new password")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
