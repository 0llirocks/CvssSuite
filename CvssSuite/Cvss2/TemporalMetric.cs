using System;
using System.Collections.Generic;

namespace Cvss.Suite.Cvss2
{
    internal class TemporalMetric : MetricGroup
    {

        private double BaseScore;

        internal TemporalMetric(Dictionary<string, string> metrics, double baseScore) : base(metrics, "ND")
        {
            AvailableMetrics = Metrics.Temporal();
            BaseScore = baseScore;
        }

        internal override double Score()
        {
            //TemporalScore = round_to_1_decimal(BaseScore*Exploitability*RemediationLevel * ReportConfidence)

            return Math.Round((BaseScore * MetricScore(Metrics.Exploitability) * MetricScore(Metrics.RemediationLevel) * MetricScore(Metrics.ReportConfidence)), 1);
        }
    }
}
