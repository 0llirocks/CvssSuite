using System.Collections.Generic;

namespace Cvss.Suite.Cvss31
{
    /// <summary>
    /// Represents CVSS v3.1 metrics.
    /// </summary>
    public static class Metrics
    {
        public static Metric AttackVector { get; } = new Metric(
                    "Attack Vector",
                    "AV",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Network", "N", 0.85),
                            new Metric.MetricValue("Adjacent", "A", 0.62),
                            new Metric.MetricValue("Local", "L", 0.55),
                            new Metric.MetricValue("Physical", "P", 0.2)
                        }
                );
        public static Metric AttackComplexity { get; } = new Metric(
            "Attack Complexity",
            "AC",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Low", "L", 0.77),
                            new Metric.MetricValue("High", "H", 0.44)
                }
        );
        public static Metric PrivilegesRequired { get; } = new Metric(
            "Privileges Required",
            "PR",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.85),
                            new Metric.MetricValue("Low", "L", 0.62),
                            new Metric.MetricValue("High", "H", 0.27)
                }
        );
        public static Metric UserInteraction { get; } = new Metric(
            "User Interaction",
            "UI",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.85),
                            new Metric.MetricValue("Required", "R", 0.62)
                }
        );
        public static Metric Scope { get; } = new Metric(
            "Scope",
            "S",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Unchanged", "U", 0.0),
                            new Metric.MetricValue("Changed", "C", 0.0)
                }
        );
        public static Metric ConfidentialityImpact { get; } = new Metric(
            "Confidentiality Impact",
            "C",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                }
        );
        public static Metric IntegrityImpact { get; } = new Metric(
            "Integrity Impact",
            "I",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                }
        );
        public static Metric AvailabilityImpact { get; } = new Metric(
            "Availability Impact",
            "A",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                }
        );
        public static Metric ExploitCodeMaturity { get; } = new Metric(
                    "Exploit Code Maturity",
                    "E",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 1.0),
                            new Metric.MetricValue("Functional", "F", 0.97),
                            new Metric.MetricValue("Proof-of-Concept", "P", 0.94),
                            new Metric.MetricValue("Unproven", "U", 0.91)
                        }
                );
        public static Metric RemediationLevel { get; } = new Metric(
            "Remediation Level",
            "RL",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("Unavailable", "U", 1.0),
                            new Metric.MetricValue("Workaround", "W", 0.97),
                            new Metric.MetricValue("Temporary Fix", "T", 0.96),
                            new Metric.MetricValue("Official Fix", "O", 0.95)
                }
        );
        public static Metric ReportConfidence { get; } = new Metric(
            "Report Confidence",
            "RC",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("Confirmed", "C", 1.0),
                            new Metric.MetricValue("Reasonable", "R", 0.96),
                            new Metric.MetricValue("Unknown", "U", 0.92)
                }
        );

        public static Metric ConfidentialityRequirement { get; } = new Metric(
                    "Confidentiality Requirement",
                    "CR",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 1.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("Low", "L", 0.5)
                        }
                );
        public static Metric IntegrityRequirement { get; } = new Metric(
            "Integrity Requirement",
            "IR",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 1.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("Low", "L", 0.5)
                }
        );
        public static Metric AvailabilityRequirement { get; } = new Metric(
            "Availability Requirement",
            "AR",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 1.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("Low", "L", 0.5)
                }
        );
        public static Metric ModifiedAttackVector { get; } = new Metric(
            "Modified Attack Vector",
            "MAV",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("Network", "N", 0.85),
                            new Metric.MetricValue("Adjacent", "A", 0.62),
                            new Metric.MetricValue("Local", "L", 0.55),
                            new Metric.MetricValue("Physical", "P", 0.2)
                }
        );
        public static Metric ModifiedAttackComplexity { get; } = new Metric(
            "Modified Attack Complexity",
            "MAC",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("Low", "L", 0.77),
                            new Metric.MetricValue("High", "H", 0.44)
                }
        );
        public static Metric ModifiedPrivilegesRequired { get; } = new Metric(
            "Modified Privileges Required",
            "MPR",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("None", "N", 0.85),
                            new Metric.MetricValue("Low", "L", 0.62),
                            new Metric.MetricValue("High", "H", 0.27)
                }
        );
        public static Metric ModifiedUserInteraction { get; } = new Metric(
            "Modified User Interaction",
            "MUI",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("None", "N", 0.85),
                            new Metric.MetricValue("Required", "R", 0.62)
                }
        );
        public static Metric ModifiedScope { get; } = new Metric(
            "Modified Scope",
            "MS",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 0.0),
                            new Metric.MetricValue("Unchanged", "U", 0.0),
                            new Metric.MetricValue("Changed", "C", 0.0)
                }
        );
        public static Metric ModifiedConfidentialityImpact { get; } = new Metric(
            "Modified Confidentiality Impact",
            "MC",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                }
        );
        public static Metric ModifiedIntegrityImpact { get; } = new Metric(
            "Modified Integrity Impact",
            "MI",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                }
        );
        public static Metric ModifiedAvailabilityImpact { get; } = new Metric(
            "Modified Availability Impact",
            "MA",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Not Defined", "X", 1.0),
                            new Metric.MetricValue("High", "H", 0.56),
                            new Metric.MetricValue("Low", "L", 0.22),
                            new Metric.MetricValue("None", "N", 0.0)
                }
        );

        /// <summary>
        /// Returns all available metrics.
        /// </summary>
        public static List<Metric> ToList()
        {
            var allMetrics = new List<Metric>(
                Base().Count +
                Temporal().Count +
                Environmental().Count
                );

            allMetrics.AddRange(Base());
            allMetrics.AddRange(Temporal());
            allMetrics.AddRange(Environmental());

            return allMetrics;
        }

        /// <summary>
        /// Returns base metrics.
        /// </summary>
        public static List<Metric> Base()
        {
            return new List<Metric>()
            {
                AttackVector,
                AttackComplexity,
                PrivilegesRequired,
                UserInteraction,
                Scope,
                ConfidentialityImpact,
                IntegrityImpact,
                AvailabilityImpact
            };
        }

        /// <summary>
        /// Returns temporal metrics.
        /// </summary>
        public static List<Metric> Temporal()
        {
            return new List<Metric>()
            {
                ExploitCodeMaturity,
                RemediationLevel,
                ReportConfidence
            };
        }

        /// <summary>
        /// Returns environmental metrics.
        /// </summary>
        public static List<Metric> Environmental()
        {
            return new List<Metric>()
            {
                ConfidentialityRequirement,
                IntegrityRequirement,
                AvailabilityRequirement,
                ModifiedAttackVector,
                ModifiedAttackComplexity,
                ModifiedPrivilegesRequired,
                ModifiedUserInteraction,
                ModifiedScope,
                ModifiedConfidentialityImpact,
                ModifiedIntegrityImpact,
                ModifiedAvailabilityImpact
            };
        }

    }
}
