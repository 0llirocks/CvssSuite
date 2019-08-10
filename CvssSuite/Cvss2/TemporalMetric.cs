using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cvss.Suite.Cvss2
{
    internal class TemporalMetric : MetricGroup
    {

        private double BaseScore;

        internal TemporalMetric(Dictionary<string, string> metrics, double baseScore) : base(metrics, "ND")
        {
            AvailableMetrics = new List<Metric>() {
                new Metric(
                    "Exploitability",
                    "E",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Unproven", "U", 0.85),
                            new Metric.MetricValue("Proof-of-Concept", "POC", 0.9),
                            new Metric.MetricValue("Functional", "F", 0.95),
                            new Metric.MetricValue("High", "H", 1.0),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                        }
                ),
                new Metric(
                    "Remediation Level",
                    "RL",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Official Fix", "OF", 0.87),
                            new Metric.MetricValue("Temporary Fix", "TF", 0.90),
                            new Metric.MetricValue("Workaround", "W", 0.95),
                            new Metric.MetricValue("Unavailable", "U", 1.0),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                        }
                ),
                new Metric(
                    "Report Confidence",
                    "RC",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Unconfirmed", "UC", 0.9),
                            new Metric.MetricValue("Uncorroborated", "UR", 0.95),
                            new Metric.MetricValue("Confirmed", "C", 1.0),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                        }
                )
            };
            GetValues();
            BaseScore = baseScore;
        }

        internal override double Score()
        {
            //TemporalScore = round_to_1_decimal(BaseScore*Exploitability*RemediationLevel * ReportConfidence)

            return Math.Round((BaseScore * MetricValues["Exploitability"] * MetricValues["Remediation Level"] * MetricValues["Report Confidence"]), 1);
        }
    }
}
