namespace CoreIdent.Client;

internal static class UrlHelpers
{
    public static string AppendQueryString(string baseUrl, IReadOnlyDictionary<string, string> parameters)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseUrl);
        ArgumentNullException.ThrowIfNull(parameters);

        if (Uri.TryCreate(baseUrl, UriKind.Absolute, out var absolute))
        {
            var builder = new UriBuilder(absolute);
            var query = ParseQuery(builder.Uri.ToString());

            foreach (var (k, v) in parameters)
            {
                query[k] = v;
            }

            builder.Query = string.Join("&", query.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
            return builder.Uri.ToString();
        }

        // Relative or unknown: basic append.
        var existing = ParseQuery(baseUrl);
        foreach (var (k, v) in parameters)
        {
            existing[k] = v;
        }

        var path = baseUrl.Split('?', 2)[0];
        var qs = string.Join("&", existing.Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
        return string.IsNullOrWhiteSpace(qs) ? path : $"{path}?{qs}";
    }

    public static Dictionary<string, string> ParseQuery(string url)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);

        var queryString = string.Empty;

        if (Uri.TryCreate(url, UriKind.Absolute, out var absolute))
        {
            queryString = absolute.Query;
        }
        else
        {
            var parts = url.Split('?', 2);
            queryString = parts.Length == 2 ? "?" + parts[1] : string.Empty;
        }

        var result = new Dictionary<string, string>(StringComparer.Ordinal);

        if (string.IsNullOrWhiteSpace(queryString))
        {
            return result;
        }

        var trimmed = queryString.TrimStart('?');
        foreach (var pair in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var kvp = pair.Split('=', 2);
            if (kvp.Length == 0)
            {
                continue;
            }

            var key = Uri.UnescapeDataString(kvp[0]);
            var value = kvp.Length == 2 ? Uri.UnescapeDataString(kvp[1]) : string.Empty;
            result[key] = value;
        }

        return result;
    }
}
