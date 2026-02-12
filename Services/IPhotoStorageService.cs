using Microsoft.AspNetCore.Http;

namespace BookwormsOnline.Services;

public interface IPhotoStorageService
{
    Task<string> SavePhotoAsync(IFormFile file, CancellationToken cancellationToken = default);

    Task<FileStream?> OpenReadAsync(string fileName, CancellationToken cancellationToken = default);

    Task DeleteIfExistsAsync(string fileName, CancellationToken cancellationToken = default);
}
