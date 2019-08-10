using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cvss.Suite.Helpers;

namespace Cvss.Suite.Cvss30
{
    internal class TemporalMetric : MetricGroup
    {

        private double BaseScore;

        internal TemporalMetric(Dictionary<string, string> metrics, double baseScore) : base(metrics, "X")
        {
            AvailableMetrics = new List<Metric>() {
                new Metric(
                    "Exploit Code Maturity",
                    "E",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 1.0),
                            new Metric.MetricValue("Functional", "F", 0.97),
                            new Metric.MetricValue("Proof-of-Concept", "P", 0.94),
                            new Metric.MetricValue("Unproven", "U", 0.91)
                        }
                ),
                new Metric(
                    "Remediation Level",
                    "RL",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("Unavailable", "U", 1.0),
                            new Metric.MetricValue("Workaround", "W", 0.97),
                            new Metric.MetricValue("Temporary Fix", "T", 0.96),
                            new Metric.MetricValue("Official Fix", "O", 0.95)
                        }
                ),
                new Metric(
                    "Report Confidence",
                    "RC",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("Confirmed", "C", 1.0),
                            new Metric.MetricValue("Reasonable", "R", 0.96),
                            new Metric.MetricValue("Unknown", "U", 0.92)
                        }
                )
            };
            GetValues();
            BaseScore = baseScore;
        }

        internal override double Score()
        {
            //TemporalScore = Round up(BaseScore × ExploitCodeMaturity × RemediationLevel × ReportConfidence)

            return (BaseScore * MetricValues["Exploit Code Maturity"] * MetricValues["Remediation Level"] * MetricValues["Report Confidence"]).RoundUp();
        }

        internal double ScoreWithoutBase()
        {
            return MetricValues["Exploit Code Maturity"] * MetricValues["Remediation Level"] * MetricValues["Report Confidence"];
        }
    }
}
