using System.Collections.Generic;

namespace Cvss.Suite
{
    public class Metric
    {

        public Metric(string name, string abbreviation, List<MetricValue> values)
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

            public readonly double Value;

            public MetricValue(string name, string abbreviation, double value)
            {
                Name = name;
                Abbreviation = abbreviation;
                Value = value;
            }
        }
    }
}
