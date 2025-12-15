using System.Xml.Linq;

namespace CoreIdent.Cli;

public static class CsprojEditor
{
    public static void AddPackageReferenceIfMissing(string csprojPath, string packageId, string version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(csprojPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(packageId);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);

        var doc = XDocument.Load(csprojPath);
        var project = doc.Root;
        if (project is null)
        {
            throw new InvalidOperationException("Invalid project file.");
        }

        var ns = project.Name.Namespace;
        var includeAttrName = XName.Get("Include");

        var existing = project
            .Descendants(ns + "PackageReference")
            .FirstOrDefault(e => string.Equals(e.Attribute(includeAttrName)?.Value, packageId, StringComparison.Ordinal));

        if (existing is not null)
        {
            return;
        }

        var itemGroup = project.Elements(ns + "ItemGroup")
            .FirstOrDefault(g => g.Elements(ns + "PackageReference").Any());

        if (itemGroup is null)
        {
            itemGroup = new XElement(ns + "ItemGroup");
            project.Add(itemGroup);
        }

        itemGroup.Add(new XElement(ns + "PackageReference",
            new XAttribute("Include", packageId),
            new XAttribute("Version", version)));

        doc.Save(csprojPath);
    }
}
