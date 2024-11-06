using System.Collections.Generic;

namespace Cvss.Suite.Cvss40
{
    /// <summary>
    /// Represents CVSS v4.0 metrics.
    /// </summary>
    public static class Metrics
    {
        public static Metric AttackVector { get; } = new Metric(
            "Attack Vector",
            "AV",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Network", "N", 0),
                    new Metric.MetricValue("Adjacent", "A", 0),
                    new Metric.MetricValue("Local", "L", 0),
                    new Metric.MetricValue("Physical", "P", 0)
                }
        );

        public static Metric AttackComplexity { get; } = new Metric(
            "Attack Complexity",
            "AC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric AttackRequirements { get; } = new Metric(
            "Attack Requirements",
            "AT",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Present", "P", 0)
                }
        );

        public static Metric PrivilegesRequired { get; } = new Metric(
            "Privileges Required",
            "PR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric UserInteraction { get; } = new Metric(
            "User Interaction",
            "UI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Passive", "P", 0),
                    new Metric.MetricValue("Active", "A", 0)
                }
        );

        public static Metric VulnerableSystemConfidentialityImpact { get; } = new Metric(
            "Vulnerable System Confidentiality Impact",
            "VC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric VulnerableSystemIntegrityImpact { get; } = new Metric(
            "Vulnerable System Integrity Impact",
            "VI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric VulnerableSystemAvailabilityImpact { get; } = new Metric(
            "Vulnerable System Availability Impact",
            "VA",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric SubsequentSystemConfidentialityImpact { get; } = new Metric(
            "Subsequent System Confidentiality Impact",
            "SC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric SubsequentSystemIntegrityImpact { get; } = new Metric(
            "Subsequent System Integrity Impact",
            "SI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric SubsequentSystemAvailabilityImpact { get; } = new Metric(
            "Subsequent System Availability Impact",
            "SA",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric ExploitMaturity { get; } = new Metric(
            "Exploit Maturity",
            "E",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Attacked", "A", 0),
                    new Metric.MetricValue("POC", "P", 0),
                    new Metric.MetricValue("Unreported", "U", 0)
                }
        );

        public static Metric ConfidentialityRequirement { get; } = new Metric(
            "Confidentiality Requirement",
            "CR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("High", "H", 0),
                    new Metric.MetricValue("Medium", "M", 0),
                    new Metric.MetricValue("Low", "L", 0)
                }
        );

        public static Metric IntegrityRequirement { get; } = new Metric(
            "Integrity Requirement",
            "IR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("High", "H", 0),
                    new Metric.MetricValue("Medium", "M", 0),
                    new Metric.MetricValue("Low", "L", 0)
                }
        );

        public static Metric AvailabilityRequirement { get; } = new Metric(
            "Availability Requirement",
            "AR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("High", "H", 0),
                    new Metric.MetricValue("Medium", "M", 0),
                    new Metric.MetricValue("Low", "L", 0)
                }
        );

        public static Metric ModifiedAttackVector { get; } = new Metric(
            "Modified Attack Vector",
            "MAV",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Network", "N", 0),
                    new Metric.MetricValue("Adjacent", "A", 0),
                    new Metric.MetricValue("Local", "L", 0),
                    new Metric.MetricValue("Physical", "P", 0)
                }
        );

        public static Metric ModifiedAttackComplexity { get; } = new Metric(
            "Modified Attack Complexity",
            "MAC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric ModifiedAttackRequirements { get; } = new Metric(
            "Modified Attack Requirements",
            "MAT",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Present", "P", 0)
                }
        );

        public static Metric ModifiedPrivilegesRequired { get; } = new Metric(
            "Modified Privileges Required",
            "MPR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric ModifiedUserInteraction { get; } = new Metric(
            "Modified User Interaction",
            "MUI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Passive", "P", 0),
                    new Metric.MetricValue("Active", "A", 0)
                }
        );

        public static Metric ModifiedVulnerableSystemConfidentiality { get; } = new Metric(
            "Modified Vulnerable System Confidentiality",
            "MVC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric ModifiedVulnerableSystemIntegrity { get; } = new Metric(
            "Modified Vulnerable System Integrity",
            "MVI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric ModifiedVulnerableSystemAvailability { get; } = new Metric(
            "Modified Vulnerable System Availability",
            "MVA",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("None", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric ModifiedSubsequentSystemConfidentiality { get; } = new Metric(
            "Modified Subsequent System Confidentiality",
            "MSC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Negligible", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric ModifiedSubsequentSystemIntegrity { get; } = new Metric(
            "Modified Subsequent System Integrity",
            "MSI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Negligible", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0),
                    new Metric.MetricValue("Safety", "S", 0)
                }
        );

        public static Metric ModifiedSubsequentSystemAvailability { get; } = new Metric(
            "Modified Subsequent System Availability",
            "MSA",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Negligible", "N", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("High", "H", 0),
                    new Metric.MetricValue("Safety", "S", 0)
                }
        );

        public static Metric Safety { get; } = new Metric(
            "Safety",
            "S",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Negligible", "N", 0),
                    new Metric.MetricValue("Present", "P", 0)
                }
        );

        public static Metric Automatable { get; } = new Metric(
            "Automatable",
            "AU",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("No", "N", 0),
                    new Metric.MetricValue("Yes", "Y", 0)
                }
        );

        public static Metric Recovery { get; } = new Metric(
            "Recovery",
            "R",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Automatic", "A", 0),
                    new Metric.MetricValue("User", "U", 0),
                    new Metric.MetricValue("Irrecoverable", "I", 0)
                }
        );

        public static Metric ValueDensity { get; } = new Metric(
            "Value Density",
            "V",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Diffuse", "D", 0),
                    new Metric.MetricValue("Concentrated", "C", 0)
                }
        );

        public static Metric VulnerabilityResponseEffort { get; } = new Metric(
            "Vulnerability Response Effort",
            "RE",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Low", "L", 0),
                    new Metric.MetricValue("Moderate", "M", 0),
                    new Metric.MetricValue("High", "H", 0)
                }
        );

        public static Metric ProviderUrgency { get; } = new Metric(
            "Provider Urgency",
            "U",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X", 0),
                    new Metric.MetricValue("Clear", "Clear", 0),
                    new Metric.MetricValue("Green", "Green", 0),
                    new Metric.MetricValue("Amber", "Amber", 0),
                    new Metric.MetricValue("Red", "Red", 0)
                }
        );


        /// <summary>
        /// Returns all available metrics.
        /// </summary>
        public static List<Metric> ToList()
        {
            var allMetrics = new List<Metric>(
                Base().Count +
                Threat().Count +
                Environmental().Count +
                Supplemental().Count
                );

            allMetrics.AddRange(Base());
            allMetrics.AddRange(Threat());
            allMetrics.AddRange(Environmental());
            allMetrics.AddRange(Supplemental());

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
                AttackRequirements,
                PrivilegesRequired,
                UserInteraction,
                VulnerableSystemConfidentialityImpact,
                VulnerableSystemIntegrityImpact,
                VulnerableSystemAvailabilityImpact,
                SubsequentSystemConfidentialityImpact,
                SubsequentSystemIntegrityImpact,
                SubsequentSystemAvailabilityImpact
            };
        }

        /// <summary>
        /// Returns threat metrics.
        /// </summary>
        public static List<Metric> Threat()
        {
            return new List<Metric>()
            {
                ExploitMaturity
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
                ModifiedAttackRequirements,
                ModifiedPrivilegesRequired,
                ModifiedUserInteraction,
                ModifiedVulnerableSystemConfidentiality,
                ModifiedVulnerableSystemIntegrity,
                ModifiedVulnerableSystemAvailability,
                ModifiedSubsequentSystemConfidentiality,
                ModifiedSubsequentSystemIntegrity,
                ModifiedSubsequentSystemAvailability
            };
        }

        /// <summary>
        /// Returns supplemental metrics.
        /// </summary>
        public static List<Metric> Supplemental()
        {
            return new List<Metric>()
            {
                Safety,
                Automatable,
                Recovery,
                ValueDensity,
                VulnerabilityResponseEffort,
                ProviderUrgency
            };
        }
    }
}
