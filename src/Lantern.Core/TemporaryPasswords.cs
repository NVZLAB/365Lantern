using System.Security.Cryptography;

namespace Lantern.Core;

public static class TemporaryPasswords
{
    public static string Generate()
    {
        string[] groups = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnpqrstuvwxyz", "23456789", "!@#$%*-_+?"];
        var alphabet = string.Concat(groups);
        var value = new char[24];
        for (var i = 0; i < value.Length; i++)
        {
            var choices = i < groups.Length ? groups[i] : alphabet;
            value[i] = choices[RandomNumberGenerator.GetInt32(choices.Length)];
        }
        for (var i = value.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (value[i], value[j]) = (value[j], value[i]);
        }
        var result = new string(value);
        Array.Clear(value);
        return result;
    }
}
