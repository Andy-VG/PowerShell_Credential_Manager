using System;
using System.Security.Cryptography;

namespace PSCredentialManager.Cmdlet
{
    public static class Membership
    {
        private static char[] punctuations = "!@#$%^&*()_-+=[{]};:>|./?".ToCharArray();

        /// <summary>
        /// https://referencesource.microsoft.com/#System.Web/Security/Membership.cs,fe744ec40cace139,references
        /// </summary>
        public static string GeneratePassword(int length, int numberOfNonAlphanumericCharacters)
        {
            if (length < 1 || length > 128)
            {
                throw new ArgumentException(nameof(length));
            }

            if (numberOfNonAlphanumericCharacters > length || numberOfNonAlphanumericCharacters < 0)
            {
                throw new ArgumentException(nameof(numberOfNonAlphanumericCharacters));
            }

            string password;
            int index;
            byte[] buf;
            char[] cBuf;
            int count;

            do
            {
                buf = new byte[length];
                cBuf = new char[length];
                count = 0;

                (new RNGCryptoServiceProvider()).GetBytes(buf);

                for (int iter = 0; iter < length; iter++)
                {
                    int i = (int)(buf[iter] % 87);
                    if (i < 10)
                        cBuf[iter] = (char)('0' + i);
                    else if (i < 36)
                        cBuf[iter] = (char)('A' + i - 10);
                    else if (i < 62)
                        cBuf[iter] = (char)('a' + i - 36);
                    else
                    {
                        cBuf[iter] = punctuations[i - 62];
                        count++;
                    }
                }

                if (count < numberOfNonAlphanumericCharacters)
                {
                    int j, k;
                    Random rand = new Random();

                    for (j = 0; j < numberOfNonAlphanumericCharacters - count; j++)
                    {
                        do
                        {
                            k = rand.Next(0, length);
                        }
                        while (!Char.IsLetterOrDigit(cBuf[k]));

                        cBuf[k] = punctuations[rand.Next(0, punctuations.Length)];
                    }
                }

                password = new string(cBuf);
            }
            while (IsDangerousString(password, out index));

            return password;
        }

        private static char[] startingChars = new char[] { '<', '&' };


        /// <summary>
        /// https://referencesource.microsoft.com/System.Web/R/5bb6e742cc83d960.html
        /// </summary>
        /// <param name="c"></param>
        /// <returns></returns>
        private static bool IsAtoZ(char c)
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        /// <summary>
        /// https://referencesource.microsoft.com/#System.Web/CrossSiteScriptingValidation.cs,3c599cea73c5293b,references
        /// </summary>
        /// <param name="s"></param>
        /// <param name="matchIndex"></param>
        /// <returns></returns>
        internal static bool IsDangerousString(string s, out int matchIndex)
        {
            //bool inComment = false;
            matchIndex = 0;

            for (int i = 0; ;)
            {

                // Look for the start of one of our patterns
                int n = s.IndexOfAny(startingChars, i);

                // If not found, the string is safe
                if (n < 0) return false;

                // If it's the last char, it's safe
                if (n == s.Length - 1) return false;

                matchIndex = n;

                switch (s[n])
                {
                    case '<':
                        // If the < is followed by a letter or '!', it's unsafe (looks like a tag or HTML comment)
                        if (IsAtoZ(s[n + 1]) || s[n + 1] == '!' || s[n + 1] == '/' || s[n + 1] == '?') return true;
                        break;
                    case '&':
                        // If the & is followed by a #, it's unsafe (e.g. &#83;)
                        if (s[n + 1] == '#') return true;
                        break;
#if OBSOLETE
                case '/':
                    // Look for a starting C style comment (i.e. "/*")
                    if (s[n+1] == '*') {
                        // Remember that we're inside a comment
                        inComment = true;
                        n++;
                    }
                    break;
                case '*':
                    // If we're not inside a comment, we don't care about finding "*/".
                    if (!inComment) break;
 
                    // Look for the end of a C style comment (i.e. "*/").  If we found one,
                    // we found a full comment, which we don't allow (VSWhidbey 228396).
                    if (s[n+1] == '/') return true;
                    break;
                case 'o':
                case 'O':
                    if (IsDangerousOnString(s, n))
                        return true;
                    break;
                case 's':
                case 'S':
                    if (IsDangerousScriptString(s, n))
                        return true;
                    break;
                case 'e':
                case 'E':
                    if (IsDangerousExpressionString(s, n))
                        return true;
                    break;
#endif // OBSOLETE
                }

                // Continue searching
                i = n + 1;
            }
        }
    }
}
