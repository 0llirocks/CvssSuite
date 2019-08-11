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

        protected List<Metric> AvailableMetrics;

        internal abstract double Score();

        internal string SelectedValue(string metric)
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

        protected double MetricScore(Metric metric)
        {
            if (ExtractedMetrics.ContainsKey(metric.Abbreviation))
            {
                return metric.Values.Single(item => item.Abbreviation == ExtractedMetrics[metric.Abbreviation]).Score;
            }
            else
            {
                return metric.Values.Single(item => item.Abbreviation == NotDefined).Score;
            }
        }

        protected Dictionary<string, string> ExtractedMetrics;

        protected Dictionary<string, double> MetricValues = new Dictionary<string, double>();

        private string NotDefined;

    }
}
