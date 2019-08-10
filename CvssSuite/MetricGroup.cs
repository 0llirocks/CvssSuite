using System;
using System.Collections.Generic;
using System.Linq;

namespace Cvss.Suite
{
    internal abstract class MetricGroup
    {
        internal MetricGroup(Dictionary<string, string> metrics, string notDefined = null)
        {
            ExtractedMetrics = metrics;
            NotDefined = notDefined;
        }

        internal List<Metric> AvailableMetrics;

        internal abstract double Score();

        internal string SelectedMetric(string metric)
        {

            try
            {
                var selectedMetric = AvailableMetrics.Single(item => item.Name == metric);

                return selectedMetric.Values.Single(item => item.Abbreviation == ExtractedMetrics[selectedMetric.Abbreviation]).Name;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

        protected void GetValues()
        {
            foreach (var metric in AvailableMetrics)
            {
                if (ExtractedMetrics.ContainsKey(metric.Abbreviation))
                {
                    MetricValues[metric.Name] = metric.Values.Single(item => item.Abbreviation == ExtractedMetrics[metric.Abbreviation]).Value;
                }
                else
                {
                    MetricValues[metric.Name] = metric.Values.Single(item => item.Abbreviation == NotDefined).Value;
                }
            }
        }

        protected Dictionary<string, string> ExtractedMetrics;

        protected Dictionary<string, double> MetricValues = new Dictionary<string, double>();

        private string NotDefined;

    }
}
