using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace CoreIdent.Integration.Tests
{
    public static class HtmlFormParser
    {
        // Very basic input extractor for test purposes (not production safe)
        public static Dictionary<string, string> ExtractInputFields(string html)
        {
            var inputs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var inputRegex = new Regex("<input[^>]*name=\"(?<name>[^\"]+)\"[^>]*value=\"(?<value>[^\"]*)\"[^>]*>", RegexOptions.IgnoreCase);
            var matches = inputRegex.Matches(html);
            foreach (Match match in matches)
            {
                var name = match.Groups["name"].Value;
                var value = match.Groups["value"].Value;
                if (!string.IsNullOrEmpty(name))
                {
                    inputs[name] = value;
                }
            }
            return inputs;
        }
    }
}
