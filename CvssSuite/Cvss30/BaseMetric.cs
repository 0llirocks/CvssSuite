using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Cvss.Suite.Helpers;

namespace Cvss.Suite.Cvss30
{
    internal class BaseMetric : MetricGroup
    {

        internal BaseMetric(Dictionary<string, string> metrics) : base(metrics)
        {
            AvailableMetrics = new List<Metric>() {
                new Metric(
                    "Attack Vector",
                    "AV",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Network", "N", 0.85),
                            new Metric.MetricValue("Adjacent", "A", 0.62),
                            new Metric.MetricValue("Local", "L", 0.55),
                            new Metric.MetricValue("Physical", "P", 0.2)
                        }
                ),
                new Metric(
                    "Attack Complexity",
                    "AC",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Low", "L", 0.77),
                            new Metric.MetricValue("High", "H", 0.44)
                        }
                ),
                new Metric(
                    "Privileges Required",
                    "PR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.85),
                            new Metric.MetricValue("Low", "L", 0.62),
                            new Metric.MetricValue("High", "H", 0.27)
                        }
                ),
                new Metric(
                    "User Interaction",
                    "UI",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.85),
                            new Metric.MetricValue("Required", "R", 0.62)
                        }
                ),
                new Metric(
                    "Scope",
                    "S",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Unchanged", "U", 0.0),
                            new Metric.MetricValue("Changed", "C", 0.0)
                        }
                ),
                new Metric(
                    "Confidentiality Impact",
                    "C",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                        }
                ),
                new Metric(
                    "Integrity Impact",
                    "I",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                        }
                ),
                new Metric(
                    "Availability Impact",
                    "A",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                        }
                )
            };
            GetValues();
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

            var privilegesRequired = MetricValues["Privileges Required"];

            if(IsScopeChanged())
            {
                if (MetricValues["Privileges Required"] == 0.62) privilegesRequired = 0.68;
                if (MetricValues["Privileges Required"] == 0.27) privilegesRequired = 0.50;
            }

            var exploitability = 8.22 * MetricValues["Attack Vector"] * MetricValues["Attack Complexity"] * privilegesRequired * MetricValues["User Interaction"];

            var iscBase = 1 - ((1 - MetricValues["Confidentiality Impact"]) * (1 - MetricValues["Integrity Impact"]) * (1 - MetricValues["Availability Impact"]));

            var impact = 0.0;

            if(IsScopeChanged())
            {
                impact = 7.52 * (iscBase - 0.029) - 3.25 * Math.Pow(iscBase - 0.02, 15);
            }
            else
            {
                impact = 6.42 * iscBase;
            }

            if(impact <= 0)
            {
                return 0.0;
            }
            else if(IsScopeChanged())
            {
                return Math.Min(10, 1.08 * (impact + exploitability)).RoundUp();
            }
            else
            {
                return Math.Min(10, impact + exploitability).RoundUp();
            }
        }

        private bool IsScopeChanged()
        {
            return ExtractedMetrics["S"] == "C";
        }
    }
}
