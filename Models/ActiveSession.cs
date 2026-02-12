using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models;

public class ActiveSession
{
    [Key]
    [MaxLength(128)]
    public string SessionToken { get; set; } = string.Empty;

    [MaxLength(255)]
    public string UserId { get; set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset LastSeenUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset ExpiresAtUtc { get; set; } = DateTimeOffset.UtcNow;

    public ApplicationUser? User { get; set; }
}
