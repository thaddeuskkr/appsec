using BookwormsOnline.Options;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Services;

public class PhotoStorageService : IPhotoStorageService
{
    private static readonly byte[] JpegHeader = [0xFF, 0xD8];
    private static readonly byte[] JpegFooter = [0xFF, 0xD9];
    private static readonly HashSet<string> AllowedJpegContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "image/jpeg",
        "image/pjpeg"
    };

    private readonly string _root;
    private readonly long _maxBytes;

    public PhotoStorageService(IOptions<StorageOptions> options, IWebHostEnvironment environment)
    {
        var config = options.Value;
        _maxBytes = config.MaxPhotoBytes;
        _root = Path.IsPathRooted(config.ProfilePhotoRoot)
            ? config.ProfilePhotoRoot
            : Path.Combine(environment.ContentRootPath, config.ProfilePhotoRoot);

        Directory.CreateDirectory(_root);
    }

    public async Task<string> SavePhotoAsync(IFormFile file, CancellationToken cancellationToken = default)
    {
        if (file.Length <= 0)
        {
            throw new InvalidOperationException("Photo file is empty.");
        }

        if (file.Length > _maxBytes)
        {
            throw new InvalidOperationException($"Photo must be {_maxBytes / 1024 / 1024}MB or smaller.");
        }

        var extension = Path.GetExtension(file.FileName);
        var isJpeg = string.Equals(extension, ".jpg", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(extension, ".jpeg", StringComparison.OrdinalIgnoreCase);

        if (!isJpeg)
        {
            throw new InvalidOperationException("Only JPG photos are allowed.");
        }

        if (!AllowedJpegContentTypes.Contains(file.ContentType))
        {
            throw new InvalidOperationException("JPG files must use image/jpeg content type.");
        }

        await using var source = file.OpenReadStream();
        await using var memoryStream = new MemoryStream();
        await source.CopyToAsync(memoryStream, cancellationToken);
        var bytes = memoryStream.ToArray();

        if (!LooksLikeJpeg(bytes))
        {
            throw new InvalidOperationException("The uploaded file is not a valid JPG image.");
        }

        var normalizedExtension = ".jpg";
        var fileName = $"{Guid.NewGuid():N}{normalizedExtension}";
        var outputPath = Path.Combine(_root, fileName);
        await File.WriteAllBytesAsync(outputPath, bytes, cancellationToken);

        return fileName;
    }

    public Task<FileStream?> OpenReadAsync(string fileName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return Task.FromResult<FileStream?>(null);
        }

        var fullPath = Path.Combine(_root, fileName);
        if (!File.Exists(fullPath))
        {
            return Task.FromResult<FileStream?>(null);
        }

        var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Task.FromResult<FileStream?>(stream);
    }

    public Task DeleteIfExistsAsync(string fileName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return Task.CompletedTask;
        }

        var fullPath = Path.Combine(_root, fileName);
        if (File.Exists(fullPath))
        {
            File.Delete(fullPath);
        }

        return Task.CompletedTask;
    }

    private static bool LooksLikeJpeg(byte[] bytes)
    {
        if (bytes.Length < 4)
        {
            return false;
        }

        return bytes[0] == JpegHeader[0] && bytes[1] == JpegHeader[1] &&
               bytes[^2] == JpegFooter[0] && bytes[^1] == JpegFooter[1];
    }
}
