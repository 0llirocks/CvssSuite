using System;

namespace Cvss.Suite.Helpers
{
    /// <summary>
    /// Includes helpers used in the package.
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Round up method for CVSS v3.0.
        /// </summary>
        public static double RoundUp(this double value)
        {
            return Math.Ceiling(value * 10.0) / 10.0;
        }

        /// <summary>
        /// Round up method for CVSS v3.1.
        /// </summary>
        public static double RoundUp31(this double value)
        {
            var output = Math.Round(value * 100000);
            if ((output % 10000) == 0)
                return output / 100000.0;
            else
                return (Math.Floor(output / 10000) + 1) / 10.0;
        }

    }
}
