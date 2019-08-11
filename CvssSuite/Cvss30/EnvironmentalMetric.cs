using System;
using System.Collections.Generic;
using Cvss.Suite.Helpers;

namespace Cvss.Suite.Cvss30
{
    internal class EnvironmentalMetric : MetricGroup
    {

        private BaseMetric BaseMetric;
        private TemporalMetric TemporalMetric;

        internal EnvironmentalMetric(Dictionary<string, string> metrics) : base(metrics, "X")
        {
            AvailableMetrics = Metrics.Environmental();
            BaseMetric = new BaseMetric(metrics);
            TemporalMetric = new TemporalMetric(metrics, BaseMetric.Score());
        }

        internal override double Score()
        {

            //If (Modified Impact Sub score =< 0)  0 else,
            //If Modified Scope Unchanged Round up(Round up (Minimum [
            //          (M.Impact + M.Exploitability), 10])
            //          × Exploit Code Maturity
            //          × Remediation Level
            //          × Report Confidence)

            //If Modified Scope Changed Round up(Round up (Minimum [1.08
            //          × (M.Impact + M.Exploitability), 10])
            //          × Exploit Code Maturity
            //          × Remediation Level
            //          × Report Confidence)
            //And the modified Impact sub score is defined as,

            //If Modified Scope Unchanged 6.42 × [ISCModified]
            //If Modified Scope Changed 7.52 × [ISCModified−0.029] - 3.25 × [ISCModified−0.02]15

            //Where,

            //ISCModified = Minimum[[1−(1−M.IConf × CR)×(1−M.IInteg × IR)×(1−M.IAvail × AR)],0.915]

            //The Modified Exploitability sub score is,

            //8.22 × M.AttackVector × M.AttackComplexity × M.PrivilegeRequired × M.UserInteraction

            if (!ExtractedMetrics.ContainsKey("MS"))
            {
                return TemporalMetric.Score();
            }

            var modifiedPrivilegesRequired = MetricScore(Metrics.ModifiedPrivilegesRequired);

            if (IsModifiedScopeChanged())
            {
                if (MetricScore(Metrics.ModifiedPrivilegesRequired) == 0.62) modifiedPrivilegesRequired = 0.68;
                if (MetricScore(Metrics.ModifiedPrivilegesRequired) == 0.27) modifiedPrivilegesRequired = 0.50;
            }

            var exploitability = 8.22 * MetricScore(Metrics.ModifiedAttackVector) * MetricScore(Metrics.ModifiedAttackComplexity) * modifiedPrivilegesRequired * MetricScore(Metrics.ModifiedUserInteraction);

            var iscModified = Math.Min(1 - (
                (1 - MetricScore(Metrics.ModifiedConfidentialityImpact) * MetricScore(Metrics.ConfidentialityRequirement)) *
                (1 - MetricScore(Metrics.ModifiedIntegrityImpact) * MetricScore(Metrics.IntegrityRequirement)) *
                (1 - MetricScore(Metrics.ModifiedAvailabilityImpact) * MetricScore(Metrics.AvailabilityRequirement))
                ), 0.915);

            var modifiedImpact = 0.0;

            if (IsModifiedScopeChanged())
            {
                modifiedImpact = 7.52 * (iscModified - 0.029) - 3.25 * Math.Pow(iscModified - 0.02, 15);
            }
            else
            {
                modifiedImpact = 6.42 * iscModified;
            }

            if (modifiedImpact <= 0)
            {
                return 0.0;
            }
            else if (IsModifiedScopeChanged())
            {
                return (Math.Min(10, 1.08 * (modifiedImpact + exploitability)).RoundUp() * TemporalMetric.ScoreWithoutBase()).RoundUp();
            }
            else
            {
                return (Math.Min(10, modifiedImpact + exploitability).RoundUp() * TemporalMetric.ScoreWithoutBase()).RoundUp();
            }
        }

        private bool IsModifiedScopeChanged()
        {
            return ExtractedMetrics["MS"] == "C";
        }
    }
}
