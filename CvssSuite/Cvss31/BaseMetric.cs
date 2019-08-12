using System;
using System.Collections.Generic;
using Cvss.Suite.Helpers;

namespace Cvss.Suite.Cvss31
{
    internal class BaseMetric : MetricGroup
    {

        internal BaseMetric(Dictionary<string, string> metrics) : base(metrics)
        {
            AvailableMetrics = Metrics.Base();
        }

        internal override double Score()
        {
            //If(Impact sub score <= 0) 0 else,
            //Scope Unchanged[4] Round up (Minimum[(Impact + Exploitability), 10])
            //Scope Changed Round up(Minimum[1.08 × (Impact + Exploitability), 10])

            //Impact sub score
            //Scope Unchanged  = 6.42 × ISCBase
            //Scope Changed = 7.52 × [ISCBase−0.029] − 3.25 × [ISCBase−0.02]15

            //ISCBase = 1 - [(1−ImpactConf) × (1−ImpactInteg) × (1−ImpactAvail)]

            //Exploitability = 8.22 × AttackVector × AttackComplexity × PrivilegeRequired × UserInteraction

            var privilegesRequired = MetricScore(Metrics.PrivilegesRequired);

            if (IsScopeChanged())
            {
                if (MetricScore(Metrics.PrivilegesRequired) == 0.62) privilegesRequired = 0.68;
                if (MetricScore(Metrics.PrivilegesRequired) == 0.27) privilegesRequired = 0.50;
            }

            var exploitability = 8.22 * MetricScore(Metrics.AttackVector) * MetricScore(Metrics.AttackComplexity) * privilegesRequired * MetricScore(Metrics.UserInteraction);

            var iscBase = 1 - ((1 - MetricScore(Metrics.ConfidentialityImpact)) * (1 - MetricScore(Metrics.IntegrityImpact)) * (1 - MetricScore(Metrics.AvailabilityImpact)));

            var impact = 0.0;

            if (IsScopeChanged())
            {
                impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.Pow(iscBase - 0.02, 15);
            }
            else
            {
                impact = 6.42 * iscBase;
            }

            if (impact <= 0)
            {
                return 0.0;
            }
            else if (IsScopeChanged())
            {
                return Math.Min(10, 1.08 * (impact + exploitability)).RoundUp31();
            }
            else
            {
                return Math.Min(10, impact + exploitability).RoundUp31();
            }
        }

        private bool IsScopeChanged()
        {
            return ExtractedMetrics["S"] == "C";
        }
    }
}
