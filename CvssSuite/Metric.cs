using System.Collections.Generic;
using System.Linq;

namespace Cvss.Suite
{
    public class Metric
    {

        internal Metric(string name, string abbreviation, List<MetricValue> values)
        {
            Name = name;
            Abbreviation = abbreviation;
            Values = values;
        }

        public readonly string Name;

        public readonly string Abbreviation;

        public readonly List<MetricValue> Values;

        public struct MetricValue
        {
            public readonly string Name;

            public readonly string Abbreviation;

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
