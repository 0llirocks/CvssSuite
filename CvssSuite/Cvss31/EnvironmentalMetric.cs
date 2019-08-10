using System;
using System.Collections.Generic;
using Cvss.Suite.Helpers;

namespace Cvss.Suite.Cvss31
{
    internal class EnvironmentalMetric : MetricGroup
    {

        private BaseMetric BaseMetric;
        private TemporalMetric TemporalMetric;

        internal EnvironmentalMetric(Dictionary<string, string> metrics) : base(metrics, "X")
        {
            AvailableMetrics = new List<Metric>() {
                new Metric(
                    "Confidentiality Requirement",
                    "CR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 1.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("Low", "L", 0.5)
                        }
                ),
                new Metric(
                    "Integrity Requirement",
                    "IR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 1.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("Low", "L", 0.5)
                        }
                ),
                new Metric(
                    "Availability Requirement",
                    "AR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 1.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("Low", "L", 0.5)
                        }
                ),
                new Metric(
                    "Modified Attack Vector",
                    "MAV",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("Network", "N", 0.85),
                            new Metric.MetricValue("Adjacent", "A", 0.62),
                            new Metric.MetricValue("Local", "L", 0.55),
                            new Metric.MetricValue("Physical", "P", 0.2)
                        }
                ),
                new Metric(
                    "Modified Attack Complexity",
                    "MAC",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("Low", "L", 0.77),
                            new Metric.MetricValue("High", "H", 0.44)
                        }
                ),
                new Metric(
                    "Modified Privileges Required",
                    "MPR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("None", "N", 0.85),
                            new Metric.MetricValue("Low", "L", 0.62),
                            new Metric.MetricValue("High", "H", 0.27)
                        }
                ),
                new Metric(
                    "Modified User Interaction",
                    "MUI",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("None", "N", 0.85),
                            new Metric.MetricValue("Required", "R", 0.62)
                        }
                ),
                new Metric(
                    "Modified Scope",
                    "MS",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 0.0),
                            new Metric.MetricValue("Unchanged", "U", 0.0),
                            new Metric.MetricValue("Changed", "C", 0.0)
                        }
                ),
                new Metric(
                    "Modified Confidentiality Impact",
                    "MC",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                        }
                ),
                new Metric(
                    "Modified Integrity Impact",
                    "MI",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                        }
                ),
                new Metric(
                    "Modified Availability Impact",
                    "MA",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                        }
                )
            };
            GetValues();
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

            var modifiedPrivilegesRequired = MetricValues["Modified Privileges Required"];

            if (IsModifiedScopeChanged())
            {
                if (MetricValues["Modified Privileges Required"] == 0.62) modifiedPrivilegesRequired = 0.68;
                if (MetricValues["Modified Privileges Required"] == 0.27) modifiedPrivilegesRequired = 0.50;
            }

            var exploitability = 8.22 * MetricValues["Modified Attack Vector"] * MetricValues["Modified Attack Complexity"] * modifiedPrivilegesRequired * MetricValues["Modified User Interaction"];

            var iscModified = Math.Min(1 - (
                (1 - MetricValues["Modified Confidentiality Impact"] * MetricValues["Confidentiality Requirement"]) *
                (1 - MetricValues["Modified Integrity Impact"] * MetricValues["Integrity Requirement"]) *
                (1 - MetricValues["Modified Availability Impact"] * MetricValues["Availability Requirement"])
                ), 0.915);

            var modifiedImpact = 0.0;

            if (IsModifiedScopeChanged())
            {
                modifiedImpact = 7.52 * (iscModified - 0.029) - 3.25 * Math.Pow(iscModified * 0.9731 - 0.02, 13);
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
                return (Math.Min(10, 1.08 * (modifiedImpact + exploitability)).RoundUp31() * TemporalMetric.ScoreWithoutBase()).RoundUp31();
            }
            else
            {
                return (Math.Min(10, modifiedImpact + exploitability).RoundUp31() * TemporalMetric.ScoreWithoutBase()).RoundUp31();
            }
        }

        private bool IsModifiedScopeChanged()
        {
            return ExtractedMetrics["MS"] == "C";
        }
    }
}
