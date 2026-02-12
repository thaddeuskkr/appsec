using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Options;

public class AppUrlOptions
{
    [Required]
    [Url]
    public string PublicBaseUrl { get; set; } = "https://localhost:5075";
}
