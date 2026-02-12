using Microsoft.AspNetCore.Identity;

namespace BookwormsOnline.Models;

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = string.Empty;

    public string LastName { get; set; } = string.Empty;

    public string EncryptedCreditCard { get; set; } = string.Empty;

    public string EncryptedMobileNo { get; set; } = string.Empty;

    public string EncryptedBillingAddress { get; set; } = string.Empty;

    public string EncryptedShippingAddress { get; set; } = string.Empty;

    public string? PhotoFileName { get; set; }

    public string? CurrentSessionToken { get; set; }

    public DateTimeOffset PasswordChangedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public bool ForcePasswordChange { get; set; }

    public ICollection<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();

    public ICollection<ActiveSession> ActiveSessions { get; set; } = new List<ActiveSession>();
}
