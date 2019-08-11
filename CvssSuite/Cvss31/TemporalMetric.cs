using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cvss.Suite.Helpers;

namespace Cvss.Suite.Cvss31
{
    internal class TemporalMetric : MetricGroup
    {

        private double BaseScore;

        internal TemporalMetric(Dictionary<string, string> metrics, double baseScore) : base(metrics, "X")
        {
            AvailableMetrics = Metrics.Temporal();
            BaseScore = baseScore;
        }

        internal override double Score()
        {
            //TemporalScore = Round up(BaseScore × ExploitCodeMaturity × RemediationLevel × ReportConfidence)

            return (BaseScore * MetricScore(Metrics.ExploitCodeMaturity) * MetricScore(Metrics.RemediationLevel) * MetricScore(Metrics.ReportConfidence)).RoundUp31();
        }

        internal double ScoreWithoutBase()
        {
            return MetricScore(Metrics.ExploitCodeMaturity) * MetricScore(Metrics.RemediationLevel) * MetricScore(Metrics.ReportConfidence);
        }
    }
}
