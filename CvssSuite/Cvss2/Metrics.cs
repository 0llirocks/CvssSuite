using System.Collections.Generic;

namespace Cvss.Suite.Cvss2
{
    public static class Metrics
    {
        public static Metric AccessVector { get; } = new Metric(
                    "Access Vector",
                    "AV",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Local", "L", 0.395),
                            new Metric.MetricValue("Adjacent Network", "A", 0.646),
                            new Metric.MetricValue("Network", "N", 1.0)
                        }
                );
        public static Metric AccessComplexity { get; } = new Metric(
                    "Access Complexity",
                    "AC",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("High", "H", 0.35),
                            new Metric.MetricValue("Medium", "M", 0.61),
                            new Metric.MetricValue("Low", "L", 0.71)
                        }
                );
        public static Metric Authentication { get; } = new Metric(
            "Authentication",
            "Au",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Multiple", "M", 0.45),
                            new Metric.MetricValue("Single", "S", 0.56),
                            new Metric.MetricValue("None", "N", 0.704)
                }
        );
        public static Metric ConfidentialityImpact { get; } = new Metric(
            "Confidentiality Impact",
            "C",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Partial", "P", 0.275),
                            new Metric.MetricValue("Complete", "C", 0.660)
                }
        );
        public static Metric IntegrityImpact { get; } = new Metric(
            "Integrity Impact",
            "I",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Partial", "P", 0.275),
                            new Metric.MetricValue("Complete", "C", 0.660)
                }
        );
        public static Metric AvailabilityImpact { get; } = new Metric(
            "Availability Impact",
            "A",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Partial", "P", 0.275),
                            new Metric.MetricValue("Complete", "C", 0.660)
                }
        );
        public static Metric Exploitability { get; } = new Metric(
                    "Exploitability",
                    "E",
                    new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Unproven", "U", 0.85),
                            new Metric.MetricValue("Proof-of-Concept", "POC", 0.9),
                            new Metric.MetricValue("Functional", "F", 0.95),
                            new Metric.MetricValue("High", "H", 1.0),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                        }
                );
        public static Metric RemediationLevel { get; } = new Metric(
            "Remediation Level",
            "RL",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Official Fix", "OF", 0.87),
                            new Metric.MetricValue("Temporary Fix", "TF", 0.90),
                            new Metric.MetricValue("Workaround", "W", 0.95),
                            new Metric.MetricValue("Unavailable", "U", 1.0),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                }
        );
        public static Metric ReportConfidence { get; } = new Metric(
            "Report Confidence",
            "RC",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Unconfirmed", "UC", 0.9),
                            new Metric.MetricValue("Uncorroborated", "UR", 0.95),
                            new Metric.MetricValue("Confirmed", "C", 1.0),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                }
        );
        public static Metric CollateralDamagePotential { get; } = new Metric(
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
                );
        public static Metric TargetDistribution { get; } = new Metric(
            "Target Distribution",
            "TD",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("None", "N", 0.0),
                            new Metric.MetricValue("Low", "L", 0.25),
                            new Metric.MetricValue("Medium", "M", 0.75),
                            new Metric.MetricValue("High", "H", 1.0),
                            new Metric.MetricValue("Not Defined", "ND", 1.0),
                }
        );
        public static Metric ConfidentialityRequirement { get; } = new Metric(
            "Confidentiality Requirement",
            "CR",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Low", "L", 0.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("High", "H", 1.51),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                }
        );
        public static Metric IntegrityRequirement { get; } = new Metric(
            "Integrity Requirement",
            "IR",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Low", "L", 0.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("High", "H", 1.51),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                }
        );
        public static Metric AvailabilityRequirement { get; } = new Metric(
            "Availability Requirement",
            "AR",
            new List<Metric.MetricValue>() {
                            new Metric.MetricValue("Low", "L", 0.5),
                            new Metric.MetricValue("Medium", "M", 1.0),
                            new Metric.MetricValue("High", "H", 1.51),
                            new Metric.MetricValue("Not Defined", "ND", 1.0)
                }
        );

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

        public static List<Metric> Base()
        {
            return new List<Metric>()
            {
                AccessVector,
                AccessComplexity,
                Authentication,
                ConfidentialityImpact,
                IntegrityImpact,
                AvailabilityImpact
            };
        }

        public static List<Metric> Temporal()
        {
            return new List<Metric>()
            {
                Exploitability,
                RemediationLevel,
                ReportConfidence
            };
        }

        public static List<Metric> Environmental()
        {
            return new List<Metric>()
            {
                CollateralDamagePotential,
                TargetDistribution,
                ConfidentialityRequirement,
                IntegrityRequirement,
                AvailabilityRequirement
            };
        }
    }
}
