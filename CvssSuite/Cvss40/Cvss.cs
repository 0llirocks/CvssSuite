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
            var allMetrics = Metrics.ToList();

            // validate insifficient length (prefix + required metrics count)
            var parts = Vector.Split(new[] { '/' });
            var requiredMetrics = allMetrics.Where(m => m.Required).Select(m => m.Abbreviation).ToArray();
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
            var lastIndex = -1;
            for (int i = 1; i < parts.Length; i++)
            {
                var split = parts[i].Split(new[] { ':' });
                if (split.Length != 2 || !Metrics.ValidOrder.Contains(split[0]))
                {
                    return false;
                }

                // validate order
                var partOrder = Array.IndexOf(Metrics.ValidOrder, split[0]);
                if (partOrder <= lastIndex)
                {
                    return false;
                }
                lastIndex = partOrder;

                // validate value
                if (!Metrics.ToList().Single(m => m.Abbreviation == split[0]).Values.Any(v => v.Abbreviation == split[1]))
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
