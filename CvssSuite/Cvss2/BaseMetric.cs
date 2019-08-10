using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cvss.Suite.Cvss2
{
    internal class BaseMetric : MetricGroup
    {

        internal BaseMetric(Dictionary<string, string> metrics) : base(metrics)
        {
            AvailableMetrics = new List<Metric>() {
                new Metric(
                    "Access Vector",
                    "AV",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Local", "L", 0.395),
                            new Metric.MetricValue("Adjacent Network", "A", 0.646),
                            new Metric.MetricValue("Network", "N", 1.0)
                        }
                ),
                new Metric(
                    "Access Complexity",
                    "AC",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("High", "H", 0.35),
                            new Metric.MetricValue("Medium", "M", 0.61),
                            new Metric.MetricValue("Low", "L", 0.71)
                        }
                ),
                new Metric(
                    "Authentication",
                    "Au",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Multiple", "M", 0.45),
                            new Metric.MetricValue("Single", "S", 0.56),
                            new Metric.MetricValue("None", "N", 0.704)
                        }
                ),
                new Metric(
                    "Confidentiality Impact",
                    "C",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Partial", "P", 0.275),
                            new Metric.MetricValue("Complete", "C", 0.660)
                        }
                ),
                new Metric(
                    "Integrity Impact",
                    "I",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Partial", "P", 0.275),
                            new Metric.MetricValue("Complete", "C", 0.660)
                        }
                ),
                new Metric(
                    "Availability Impact",
                    "A",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Partial", "P", 0.275),
                            new Metric.MetricValue("Complete", "C", 0.660)
                        }
                )
            };
            GetValues();
        }

        internal override double Score()
        {
            //BaseScore = round_to_1_decimal(((0.6 * Impact) + (0.4 * Exploitability) - 1.5) * f(Impact))

            //Impact = 10.41 * (1 - (1 - ConfImpact) * (1 - IntegImpact) * (1 - AvailImpact))

            //Exploitability = 20 * AccessVector * AccessComplexity * Authentication

            //f(impact) = 0 if Impact = 0, 1.176 otherwise

            var impact = 10.41 * (1 - (1 - MetricValues["Confidentiality Impact"]) * (1 - MetricValues["Integrity Impact"]) * (1 - MetricValues["Availability Impact"]));

            var exploitability = 20 * MetricValues["Access Vector"] * MetricValues["Access Complexity"] * MetricValues["Authentication"];

            var f_impact = impact == 0.0 ? 0.0 : 1.176;

            return Math.Round((((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact), 1);
        }

        internal double AdjustedEnvironmentScore(double confidentialityRequirement, double integrityRequirement, double availabilityRequirement)
        {
            //AdjustedImpact = min(10, 10.41 * (1 - (1 - ConfImpact * ConfReq) * (1 - IntegImpact * IntegReq) * (1 - AvailImpact * AvailReq)))

            var adjustedImpact = Math.Min(10.0, 10.41 * (1 - 
                (1 - MetricValues["Confidentiality Impact"] * confidentialityRequirement) * 
                (1 - MetricValues["Integrity Impact"] * integrityRequirement) * 
                (1 - MetricValues["Availability Impact"] * availabilityRequirement)));

            var exploitability = 20 * MetricValues["Access Vector"] * MetricValues["Access Complexity"] * MetricValues["Authentication"];

            var f_impact = adjustedImpact == 0.0 ? 0.0 : 1.176;

            return Math.Round((((0.6 * adjustedImpact) + (0.4 * exploitability) - 1.5) * f_impact), 1);
        }
    }
}
