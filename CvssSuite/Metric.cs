using System.Collections.Generic;

namespace Cvss.Suite
{
    /// <summary>
    /// Base object for all metrics.
    /// </summary>
    public class Metric
    {

        internal Metric(string name, string abbreviation, List<MetricValue> values)
        {
            Name = name;
            Abbreviation = abbreviation;
            Values = values;
        }

        /// <summary>
        /// Name of the metric.
        /// </summary>
        public readonly string Name;

        /// <summary>
        /// Abbreviation of the metric.
        /// </summary>
        public readonly string Abbreviation;

        /// <summary>
        /// All available values for the metric.
        /// </summary>
        public readonly List<MetricValue> Values;

        /// <summary>
        /// Represents one available value for a metric.
        /// </summary>
        public struct MetricValue
        {
            /// <summary>
            /// Name of the value.
            /// </summary>
            public readonly string Name;

            /// <summary>
            /// Abbreviation for the value.
            /// </summary>
            public readonly string Abbreviation;

            /// <summary>
            /// Score of the value, used to calculate the base, temporal and environmental score.
            /// </summary>
            public readonly double Score;

            internal MetricValue(string name, string abbreviation, double score)
            {
                Name = name;
                Abbreviation = abbreviation;
                Score = score;
            }
        }
    }
}
