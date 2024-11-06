using System;
using System.Collections.Generic;
using System.Linq;

namespace Cvss.Suite.Cvss40
{
    /// <summary>
    /// Represents a CVSS v4.0 object.
    /// </summary>
    public class Cvss : CvssBase
    {
        internal Cvss(string vector, double version) : base(vector, version)
        {
            if (!IsValid()) return;

            ExtractedMetrics = ExtractMetrics();
            BaseMetric = new BaseMetric(ExtractedMetrics);
        }

        /// <summary>
        /// Returns whether the CVSS object is valid or not.
        /// </summary>
        public override bool IsValid()
        {
            // validate insifficient length (prefix + required metrics count)
            var parts = Vector.Split(new[] { '/' });
            var requiredMetrics = new string[] { "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA" };
            if (parts.Length < requiredMetrics.Length + 1)
            {
                return false;
            }

            // validate correct prefix
            if (parts[0] != "CVSS:4.0")
            {
                return false;
            }

            // validate required metrics
            for (int i = 0; i < requiredMetrics.Length; i++)
            {
                var split = parts[i + 1].Split(new[] { ':' });
                if (split.Length != 2 || split[0] != requiredMetrics[i])
                {
                    return false;
                }
            }

            // validate metric order and values
            var validMetricsOrder = requiredMetrics.Concat(new string[] { "E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA", "S", "AU", "R", "V", "RE", "U" }).ToList();
            var validMetricValues = new Dictionary<string, string[]>()
            {
                {"AV", new [] {"N","A","L","P"}},
                {"AC", new [] {"L","H"}},
                {"AT", new [] {"N","P"}},
                {"PR", new [] {"N","L","H"}},
                {"UI", new [] {"N","P","A"}},
                {"VC", new [] {"H","L","N"}},
                {"VI", new [] {"H","L","N"}},
                {"VA", new [] {"H","L","N"}},
                {"SC", new [] {"H","L","N"}},
                {"SI", new [] {"H","L","N"}},
                {"SA", new [] {"H","L","N"}},
                {"E", new [] {"X","A","P","U"}},
                {"CR", new [] {"X","H","M","L"}},
                {"IR", new [] {"X","H","M","L"}},
                {"AR", new [] {"X","H","M","L"}},
                {"MAV", new [] {"X","N","A","L","P"}},
                {"MAC", new [] {"X","L","H"}},
                {"MAT", new [] {"X","N","P"}},
                {"MPR", new [] {"X","N","L","H"}},
                {"MUI", new [] {"X","N","P","A"}},
                {"MVC", new [] {"X","N","L","H"}},
                {"MVI", new [] {"X","N","L","H"}},
                {"MVA", new [] {"X","N","L","H"}},
                {"MSC", new [] {"X","N","L","H"}},
                {"MSI", new [] {"X","N","L","H","S"}},
                {"MSA", new [] {"X","N","L","H","S"}},
                {"S", new [] {"X","N","P"}},
                {"AU", new [] {"X","N","Y"}},
                {"R", new [] {"X","A","U","I"}},
                {"V", new [] {"X","D","C"}},
                {"RE", new [] {"X","L","M","H"}},
                {"U", new [] {"X","Clear","Green","Amber","Red"}},
            };
            var lastIndex = -1;
            for (int i = 1; i < parts.Length; i++)
            {
                var split = parts[i].Split(new[] { ':' });
                if (split.Length != 2 || !validMetricsOrder.Contains(split[0]))
                {
                    return false;
                }

                // validate order
                var partOrder = validMetricsOrder.IndexOf(split[0]);
                if (partOrder <= lastIndex)
                {
                    return false;
                }
                lastIndex = partOrder;

                // validate value
                if (!validMetricValues[split[0]].Contains(split[1]))
                {
                    return false;
                }
            }

            return true;
        }


        /// <summary>
        /// Returns the overall score of the CVSS object.
        /// </summary>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public override double OverallScore()
        {
            if (!IsValid()) throw new ArgumentException();

            return BaseScore();
        }

        /// <summary>
        /// Returns the selected value for a metric.
        /// </summary>
        /// <returns>
        /// Returns the selected value or empty string if metric is not found.
        /// </returns>
        /// <example>
        /// <code>
        /// var selected = cvss.SelectedValue("Attack Vector");
        /// returns "Network"
        /// </code>
        /// </example>
        /// <param name="metric">A valid metric e.g. "Attack Vector", "User Interaction", "Exploit Maturity".</param>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public override string SelectedMetric(string metric)
        {
            if (!IsValid()) throw new ArgumentException();

            return BaseMetric.SelectedValue(metric) ?? "";
        }
    }
}
