using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cvss.Suite.Tests
{
    [TestClass]
    public class Cvss40
    {
        [DataTestMethod]
        // Base
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", 8.3, "High")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 8.3, "High")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P", 8.5, "High")]
        [DataRow("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/S:P", 8.6, "High")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 4.6, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 6.9, "Medium")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N", 5.9, "Medium")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 9.4, "Critical")]
        [DataRow("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:H/SA:N/S:P/V:D", 8.3, "High")]
        [DataRow("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:H/SI:N/SA:H", 6.4, "Medium")]
        [DataRow("CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 8.6, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.2, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L", 8.7, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1, "Medium")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.5, "High")]
        [DataRow("CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 5.4, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 8.7, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 6.9, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N", 6.9, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L", 6.9, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, "Critical")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:H", 7.8, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:L/SA:L/MSI:N/MSA:N", 6.9, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/V:C/RE:L", 9.4, "Critical")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C", 8.7, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H", 6.4, "Medium")]
        // Base + Threat
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 5.2, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A", 8.7, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", 10, "Critical")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.3, "Critical")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I", 9.3, "Critical")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/R:I", 8.7, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", 8.2, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L/E:U", 6.6, "Medium")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U", 5.6, "Medium")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A", 9.2, "Critical")]
        // Base + Enviromental
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N/CR:H/IR:L/AR:L/MAV:N/MAC:H/MVC:H/MVI:L/MVA:L", 8.1, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:L/IR:H/AR:L/MAV:L/MAC:H/MAT:N/MPR:N/MUI:N/MVC:N/MVI:H/MVA:L/MSC:N/MSI:S/MSA:L", 7.0, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:L/IR:H/AR:H/MAV:A/MAC:H/MAT:N/MPR:L/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S", 7.4, "High")]
        [DataRow("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/CR:M/IR:H/AR:M/MAV:N/MAC:H/MAT:N/MPR:L/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:H", 8.7, "High")]
        [DataRow("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/MSI:S/S:P", 9.7, "Critical")]
        // Base + Threat + Enviromental
        [DataRow("CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/MAC:L/MAT:N/MVC:N/MVI:N/MVA:L", 5.5, "Medium")]
        public void ValidCvss40Vectors(string vector, double baseScore, string severity)
        {
            var cvss = Cvss.Suite.CvssSuite.Create(vector);

            Assert.AreEqual(true, cvss.IsValid());
            Assert.AreEqual(4.0, cvss.Version);
            Assert.AreEqual(baseScore, cvss.BaseScore());
            Assert.AreEqual(severity, cvss.Severity());
        }

        [DataTestMethod]
        [DataRow("CVSS:4.0/")]
        [DataRow("CVSS:4.0/AC:L/AV:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")]
        [DataRow("CVSS:4.0/AV:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")]
        [DataRow("CVSS:4.0/AV:L/AC:L/AT:X/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")]
        public void InvalidCvss40Vectors(string vector)
        {
            var cvss = Cvss.Suite.CvssSuite.Create(vector);

            Assert.AreEqual(false, cvss.IsValid());
            Assert.AreEqual(4.0, cvss.Version);

            Assert.ThrowsException<ArgumentException>(() => cvss.BaseScore());
            Assert.ThrowsException<ArgumentException>(() => cvss.EnvironmentalScore());
            Assert.ThrowsException<ArgumentException>(() => cvss.OverallScore());
            Assert.ThrowsException<ArgumentException>(() => cvss.SelectedMetric(""));
            Assert.ThrowsException<ArgumentException>(() => cvss.Severity());
            Assert.ThrowsException<ArgumentException>(() => cvss.TemporalScore());
        }

        [DataTestMethod]
        [DataRow("Attack Vector", "Local")]
        [DataRow("Attack Complexity", "High")]
        [DataRow("Privileges Required", "Low")]
        [DataRow("User Interaction", "Passive")]
        [DataRow("Safety", "Negligible")]
        [DataRow("Vulnerable System Confidentiality Impact", "Low")]
        [DataRow("Subsequent System Integrity Impact", "None")]
        [DataRow("Vulnerable System Availability Impact", "High")]
        [DataRow("Invalid", "")]
        public void SelectedCvss40Metric(string metric, string selectedMetric)
        {
            var cvss = Cvss.Suite.CvssSuite.Create("CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N/S:N");

            Assert.AreEqual(selectedMetric, cvss.SelectedMetric(metric));
        }
    }
}
