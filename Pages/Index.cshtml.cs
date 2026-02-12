using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages;

[Authorize]
public class IndexModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IFieldEncryptionService _encryptionService;
    private readonly IPasswordPolicyService _passwordPolicyService;

    public IndexModel(
        UserManager<ApplicationUser> userManager,
        IFieldEncryptionService encryptionService,
        IPasswordPolicyService passwordPolicyService)
    {
        _userManager = userManager;
        _encryptionService = encryptionService;
        _passwordPolicyService = passwordPolicyService;
    }

    public string FullName { get; private set; } = string.Empty;

    public string Email { get; private set; } = string.Empty;

    public string MobileNumber { get; private set; } = string.Empty;

    public string BillingAddress { get; private set; } = string.Empty;

    public string ShippingAddress { get; private set; } = string.Empty;

    public string MaskedCreditCard { get; private set; } = string.Empty;

    public string? CurrentUserId { get; private set; }

    public bool HasProfilePhoto { get; private set; }

    public string? StatusMessage { get; private set; }

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Account/Login");
        }

        if (_passwordPolicyService.IsPasswordExpired(user))
        {
            user.ForcePasswordChange = true;
            await _userManager.UpdateAsync(user);
            return RedirectToPage("/Account/ChangePassword", new { expired = true });
        }

        CurrentUserId = user.Id;
        HasProfilePhoto = !string.IsNullOrWhiteSpace(user.PhotoFileName);

        var firstName = InputEncodingService.DecodeFromStorage(user.FirstName);
        var lastName = InputEncodingService.DecodeFromStorage(user.LastName);
        FullName = $"{firstName} {lastName}".Trim();
        Email = user.Email ?? string.Empty;

        try
        {
            var decryptedCard = _encryptionService.Decrypt(user.EncryptedCreditCard);
            MobileNumber = InputEncodingService.DecodeFromStorage(_encryptionService.Decrypt(user.EncryptedMobileNo));
            BillingAddress = InputEncodingService.DecodeFromStorage(_encryptionService.Decrypt(user.EncryptedBillingAddress));
            ShippingAddress = InputEncodingService.DecodeFromStorage(_encryptionService.Decrypt(user.EncryptedShippingAddress));
            MaskedCreditCard = MaskCard(decryptedCard);
        }
        catch
        {
            StatusMessage = "Some encrypted profile fields could not be read.";
        }

        return Page();
    }

    private static string MaskCard(string card)
    {
        var digits = new string(card.Where(char.IsDigit).ToArray());
        if (digits.Length <= 4)
        {
            return "****";
        }

        return new string('*', digits.Length - 4) + digits[^4..];
    }
}
