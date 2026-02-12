using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Options;

public class StorageOptions
{
    [Required]
    public string ProfilePhotoRoot { get; set; } = "App_Data/ProfilePhotos";

    [Range(1024, 10 * 1024 * 1024)]
    public long MaxPhotoBytes { get; set; } = 2 * 1024 * 1024;

    [Required]
    public string DataProtectionKeysPath { get; set; } = "App_Data/DataProtectionKeys";
}
