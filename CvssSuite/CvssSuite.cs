using System.Linq;

namespace Cvss.Suite
{
    /// <summary>
    /// Entry point for CVSS Suite
    /// </summary>
    public static class CvssSuite
    {
        /// <summary>
        /// Method to create the main Cvss object
        /// </summary>
        /// <returns>
        /// The corressponding CvssBase object
        /// </returns>
        /// <example>
        /// <code>
        /// CvssSuite.Create("AV:N/AC:L/Au:N/C:C/I:C/A:C");
        /// </code>
        /// </example>
        public static CvssBase Create(string vector)
        {
            var version = GetVersion(vector);

            if (version == 2) return new Cvss2.Cvss(vector, version);
            if (version == 3.0) return new Cvss30.Cvss(vector, version);
            if (version == 3.1) return new Cvss31.Cvss(vector, version);
            else return new InvalidCvss(vector);
        }

        private static CvssVersion[] versions = new CvssVersion[] 
        {
            new CvssVersion(2, "AV:"),
            new CvssVersion(3.0, "CVSS:3.0/"),
            new CvssVersion(3.1, "CVSS:3.1/")
        };

        private static double GetVersion(string vector)
        {
            if (vector == null) return 0;
            var version = versions.SingleOrDefault(item => vector.StartsWith(item.Vector));
            return version.Equals(null) ? 0 : version.Version;
        }
    }

    internal struct CvssVersion
    {
        internal readonly double Version;
        internal readonly string Vector;

        internal CvssVersion(double version, string vector)
        {
            Version = version;
            Vector = vector;
        }
    }
}
