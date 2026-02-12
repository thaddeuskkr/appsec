using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Validation;

[AttributeUsage(AttributeTargets.Property)]
public sealed class LuhnAttribute : ValidationAttribute
{
    public LuhnAttribute()
        : base("Credit card number is invalid.")
    {
    }

    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
    {
        var input = value as string;
        if (string.IsNullOrWhiteSpace(input))
        {
            return ValidationResult.Success;
        }

        var digits = input.Where(char.IsDigit).Select(ch => ch - '0').ToArray();
        if (digits.Length < 12 || digits.Length > 19)
        {
            return new ValidationResult(ErrorMessage);
        }

        var sum = 0;
        var shouldDouble = false;

        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var digit = digits[i];
            if (shouldDouble)
            {
                digit *= 2;
                if (digit > 9)
                {
                    digit -= 9;
                }
            }

            sum += digit;
            shouldDouble = !shouldDouble;
        }

        return sum % 10 == 0 ? ValidationResult.Success : new ValidationResult(ErrorMessage);
    }
}
