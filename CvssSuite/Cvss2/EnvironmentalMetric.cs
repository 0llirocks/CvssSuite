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
            AvailableMetrics = Metrics.Environmental();
            BaseMetric = new BaseMetric(metrics);
            TemporalMetric = new TemporalMetric(metrics, BaseMetric.AdjustedEnvironmentScore(
                MetricScore(Metrics.ConfidentialityRequirement),
                MetricScore(Metrics.IntegrityRequirement),
                MetricScore(Metrics.AvailabilityRequirement))
                );
        }

        internal override double Score()
        {

            //EnvironmentalScore = round_to_1_decimal((AdjustedTemporal + (10 - AdjustedTemporal) * CollateralDamagePotential) * TargetDistribution)

            //AdjustedTemporal = TemporalScore recomputed with the BaseScore's Impact sub-equation replaced with the AdjustedImpact equation

            //AdjustedImpact = min(10, 10.41 * (1 - (1 - ConfImpact * ConfReq) * (1 - IntegImpact * IntegReq) * (1 - AvailImpact * AvailReq)))

            var adjustedTemporal = TemporalMetric.Score();

            return Math.Round((adjustedTemporal + (10 - adjustedTemporal) * MetricScore(Metrics.CollateralDamagePotential)) * MetricScore(Metrics.TargetDistribution), 1);
        }
    }
}
