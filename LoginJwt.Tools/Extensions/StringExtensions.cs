using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace LoginJwt.Tools.Extensions
{
    public static class StringExtensions
    {
        public static bool IsAnyNullOrWhiteSpace(this string theString, params string[] stringsToValidate)
        {
            return string.IsNullOrWhiteSpace(theString) || stringsToValidate?.Any(string.IsNullOrWhiteSpace) != false;
        }
        public static bool IsValidGuid(this string value)
        {
            return !string.IsNullOrWhiteSpace(value) && Guid.TryParse(value, out var resultGuid) &&
                   Guid.Empty != resultGuid;
        }

        public static bool IsValidEmail(this string emailAddress)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
                return false;

            // Return true if strIn is in valid e-mail format.
            return Regex.IsMatch(emailAddress,
                @"^(?("")(""[^""]+?""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))" +
                @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-\w]*[0-9a-z]*\.)+[a-z0-9]{2,17}))$",
                RegexOptions.IgnoreCase);

        }
    }
}
