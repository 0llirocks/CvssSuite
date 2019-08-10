using System;
using System.Collections.Generic;

namespace Cvss.Suite.Cvss2
{
    internal class EnvironmentalMetric : MetricGroup
    {

        private BaseMetric BaseMetric;
        private TemporalMetric TemporalMetric;

        internal EnvironmentalMetric(Dictionary<string, string> metrics) : base(metrics, "ND")
        {
            AvailableMetrics = new List<Metric>() {
                new Metric(
                    "Collateral Damage Potential",
                    "CDP",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Low", "L", 0.1),
                            new Metric.MetricValue("Low-Medium", "LM", 0.3),
                            new Metric.MetricValue("Medium-High", "MH", 0.4),
                            new Metric.MetricValue("High", "H", 0.5),
                            new Metric.MetricValue("Not Defined", "ND", 0.0)
                        }
                ),
                new Metric(
                    "Target Distribution",
                    "TD",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Low", "L", 0.25),
                            new Metric.MetricValue("Medium", "M", 0.75),
                            new Metric.MetricValue("High", "H", 1.0),
                            new Metric.MetricValue("Not Defined", "ND", 1.0),
                        }
                ),
                new Metric(
                    "Confidentiality Requirement",
                    "CR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Low", "L", 0.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("High", "H", 1.51),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                        }
                ),
                new Metric(
                    "Integrity Requirement",
                    "IR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Low", "L", 0.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("High", "H", 1.51),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                        }
                ),
                new Metric(
                    "Availability Requirement",
                    "AR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Low", "L", 0.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("High", "H", 1.51),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                        }
                )
            };
            GetValues();
            BaseMetric = new BaseMetric(metrics);
            TemporalMetric = new TemporalMetric(metrics, BaseMetric.AdjustedEnvironmentScore(
                MetricValues["Confidentiality Requirement"], 
                MetricValues["Integrity Requirement"], 
                MetricValues["Availability Requirement"]));
        }

        internal override double Score()
        {

            //EnvironmentalScore = round_to_1_decimal((AdjustedTemporal + (10 - AdjustedTemporal) * CollateralDamagePotential) * TargetDistribution)

            //AdjustedTemporal = TemporalScore recomputed with the BaseScore's Impact sub-equation replaced with the AdjustedImpact equation

            //AdjustedImpact = min(10, 10.41 * (1 - (1 - ConfImpact * ConfReq) * (1 - IntegImpact * IntegReq) * (1 - AvailImpact * AvailReq)))

            var adjustedTemporal = TemporalMetric.Score();

            return Math.Round((adjustedTemporal + (10 - adjustedTemporal) * MetricValues["Collateral Damage Potential"]) * MetricValues["Target Distribution"], 1);
        }
    }
}
