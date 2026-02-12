namespace BookwormsOnline.Models;

public class PasswordHistory
{
    public int Id { get; set; }

    public string UserId { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public ApplicationUser User { get; set; } = null!;
}
