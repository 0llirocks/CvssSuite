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
            AvailableMetrics = Metrics.Base();
        }

        internal override double Score()
        {
            //Impact = 10.41 * (1 - (1 - ConfImpact) * (1 - IntegImpact) * (1 - AvailImpact))

            //Exploitability = 20 * AccessVector * AccessComplexity * Authentication

            //f(impact) = 0 if Impact = 0, 1.176 otherwise

            //BaseScore = round_to_1_decimal(((0.6 * Impact) + (0.4 * Exploitability) - 1.5) * f(Impact))

            var impact = 10.41 * (1 - (1 - MetricScore(Metrics.ConfidentialityImpact)) * (1 - MetricScore(Metrics.IntegrityImpact)) * (1 - MetricScore(Metrics.AvailabilityImpact)));

            var exploitability = 20 * MetricScore(Metrics.AccessVector) * MetricScore(Metrics.AccessComplexity) * MetricScore(Metrics.Authentication);

            var f_impact = impact == 0.0 ? 0.0 : 1.176;

            return Math.Round((((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact), 1);
        }

        internal double AdjustedEnvironmentScore(double confidentialityRequirement, double integrityRequirement, double availabilityRequirement)
        {
            //AdjustedImpact = min(10, 10.41 * (1 - (1 - ConfImpact * ConfReq) * (1 - IntegImpact * IntegReq) * (1 - AvailImpact * AvailReq)))

            var adjustedImpact = Math.Min(10.0, 10.41 * (1 - 
                (1 - MetricScore(Metrics.ConfidentialityImpact) * confidentialityRequirement) * 
                (1 - MetricScore(Metrics.IntegrityImpact) * integrityRequirement) * 
                (1 - MetricScore(Metrics.AvailabilityImpact) * availabilityRequirement)));

            var exploitability = 20 * MetricScore(Metrics.AccessVector) * MetricScore(Metrics.AccessComplexity) * MetricScore(Metrics.Authentication);

            var f_impact = adjustedImpact == 0.0 ? 0.0 : 1.176;

            return Math.Round((((0.6 * adjustedImpact) + (0.4 * exploitability) - 1.5) * f_impact), 1);
        }
    }
}
