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
                    new Metric.MetricValue("Network", "N"),
                    new Metric.MetricValue("Adjacent", "A"),
                    new Metric.MetricValue("Local", "L"),
                    new Metric.MetricValue("Physical", "P")
                }
        );

        public static Metric AttackComplexity { get; } = new Metric(
            "Attack Complexity",
            "AC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric AttackRequirements { get; } = new Metric(
            "Attack Requirements",
            "AT",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Present", "P")
                }
        );

        public static Metric PrivilegesRequired { get; } = new Metric(
            "Privileges Required",
            "PR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric UserInteraction { get; } = new Metric(
            "User Interaction",
            "UI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Passive", "P"),
                    new Metric.MetricValue("Active", "A")
                }
        );

        public static Metric VulnerableSystemConfidentialityImpact { get; } = new Metric(
            "Vulnerable System Confidentiality Impact",
            "VC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric VulnerableSystemIntegrityImpact { get; } = new Metric(
            "Vulnerable System Integrity Impact",
            "VI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric VulnerableSystemAvailabilityImpact { get; } = new Metric(
            "Vulnerable System Availability Impact",
            "VA",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric SubsequentSystemConfidentialityImpact { get; } = new Metric(
            "Subsequent System Confidentiality Impact",
            "SC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric SubsequentSystemIntegrityImpact { get; } = new Metric(
            "Subsequent System Integrity Impact",
            "SI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric SubsequentSystemAvailabilityImpact { get; } = new Metric(
            "Subsequent System Availability Impact",
            "SA",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric ExploitMaturity { get; } = new Metric(
            "Exploit Maturity",
            "E",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Attacked", "A"),
                    new Metric.MetricValue("POC", "P"),
                    new Metric.MetricValue("Unreported", "U")
                }
        );

        public static Metric ConfidentialityRequirement { get; } = new Metric(
            "Confidentiality Requirement",
            "CR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("High", "H"),
                    new Metric.MetricValue("Medium", "M"),
                    new Metric.MetricValue("Low", "L")
                }
        );

        public static Metric IntegrityRequirement { get; } = new Metric(
            "Integrity Requirement",
            "IR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("High", "H"),
                    new Metric.MetricValue("Medium", "M"),
                    new Metric.MetricValue("Low", "L")
                }
        );

        public static Metric AvailabilityRequirement { get; } = new Metric(
            "Availability Requirement",
            "AR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("High", "H"),
                    new Metric.MetricValue("Medium", "M"),
                    new Metric.MetricValue("Low", "L")
                }
        );

        public static Metric ModifiedAttackVector { get; } = new Metric(
            "Modified Attack Vector",
            "MAV",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Network", "N"),
                    new Metric.MetricValue("Adjacent", "A"),
                    new Metric.MetricValue("Local", "L"),
                    new Metric.MetricValue("Physical", "P")
                }
        );

        public static Metric ModifiedAttackComplexity { get; } = new Metric(
            "Modified Attack Complexity",
            "MAC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric ModifiedAttackRequirements { get; } = new Metric(
            "Modified Attack Requirements",
            "MAT",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Present", "P")
                }
        );

        public static Metric ModifiedPrivilegesRequired { get; } = new Metric(
            "Modified Privileges Required",
            "MPR",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric ModifiedUserInteraction { get; } = new Metric(
            "Modified User Interaction",
            "MUI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Passive", "P"),
                    new Metric.MetricValue("Active", "A")
                }
        );

        public static Metric ModifiedVulnerableSystemConfidentiality { get; } = new Metric(
            "Modified Vulnerable System Confidentiality",
            "MVC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric ModifiedVulnerableSystemIntegrity { get; } = new Metric(
            "Modified Vulnerable System Integrity",
            "MVI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric ModifiedVulnerableSystemAvailability { get; } = new Metric(
            "Modified Vulnerable System Availability",
            "MVA",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("None", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric ModifiedSubsequentSystemConfidentiality { get; } = new Metric(
            "Modified Subsequent System Confidentiality",
            "MSC",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Negligible", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric ModifiedSubsequentSystemIntegrity { get; } = new Metric(
            "Modified Subsequent System Integrity",
            "MSI",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Negligible", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H"),
                    new Metric.MetricValue("Safety", "S")
                }
        );

        public static Metric ModifiedSubsequentSystemAvailability { get; } = new Metric(
            "Modified Subsequent System Availability",
            "MSA",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Negligible", "N"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("High", "H"),
                    new Metric.MetricValue("Safety", "S")
                }
        );

        public static Metric Safety { get; } = new Metric(
            "Safety",
            "S",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Negligible", "N"),
                    new Metric.MetricValue("Present", "P")
                }
        );

        public static Metric Automatable { get; } = new Metric(
            "Automatable",
            "AU",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("No", "N"),
                    new Metric.MetricValue("Yes", "Y")
                }
        );

        public static Metric Recovery { get; } = new Metric(
            "Recovery",
            "R",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Automatic", "A"),
                    new Metric.MetricValue("User", "U"),
                    new Metric.MetricValue("Irrecoverable", "I")
                }
        );

        public static Metric ValueDensity { get; } = new Metric(
            "Value Density",
            "V",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Diffuse", "D"),
                    new Metric.MetricValue("Concentrated", "C")
                }
        );

        public static Metric VulnerabilityResponseEffort { get; } = new Metric(
            "Vulnerability Response Effort",
            "RE",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Low", "L"),
                    new Metric.MetricValue("Moderate", "M"),
                    new Metric.MetricValue("High", "H")
                }
        );

        public static Metric ProviderUrgency { get; } = new Metric(
            "Provider Urgency",
            "U",
            new List<Metric.MetricValue>() {
                    new Metric.MetricValue("Not Defined", "X"),
                    new Metric.MetricValue("Clear", "Clear"),
                    new Metric.MetricValue("Green", "Green"),
                    new Metric.MetricValue("Amber", "Amber"),
                    new Metric.MetricValue("Red", "Red")
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
