using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cvss.Suite.Tests
{
    [TestClass]
    public class Cvss31
    {

        [DataTestMethod]
        //Base Score
        [DataRow("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.6, 2.6, 2.6, 2.6, "Low")]
        [DataRow("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L", 4.2, 4.2, 4.2, 4.2, "Medium")]
        [DataRow("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:H", 7.9, 7.9, 7.9, 7.9, "High")]
        [DataRow("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H", 9.9, 9.9, 9.9, 9.9, "Critical")]

        //Base Score + Temporal Score
        [DataRow("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N/E:P/RL:T/RC:C", 4.0, 3.7, 3.7, 3.7, "Low")]
        [DataRow("CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U", 5.0, 4.6, 4.6, 4.6, "Medium")]
        [DataRow("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C", 10.0, 8.7, 8.7, 8.7, "High")]
        [DataRow("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C", 10.0, 10.0, 10.0, 10.0, "Critical")]

        //Base Score + Environmental Score
        [DataRow("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:H/CR:L/IR:L/AR:M/MAV:P/MAC:L/MPR:H/MUI:R/MS:U/MC:N/MI:H/MA:L", 7.1, 7.1, 3.1, 3.1, "Low")]
        [DataRow("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N/CR:H/IR:H/AR:M/MAV:P/MAC:L/MPR:H/MUI:R/MS:U/MC:N/MI:H/MA:L", 7.5, 7.5, 5.9, 5.9, "Medium")]
        [DataRow("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H", 5.0, 5.0, 7.3, 7.3, "High")]
        [DataRow("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:L", 9.9, 9.9, 9.7, 9.7, "Critical")]

        //Base Score + Temporal Score + Environmental Score
        [DataRow("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N/E:U/RL:O/RC:U/CR:H/IR:H/AR:M/MAV:A/MAC:L/MPR:H/MUI:R/MS:U/MC:N/MI:L/MA:L", 5.4, 4.3, 3.1, 3.1, "Low")]
        [DataRow("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:H/MA:H", 10.0, 8.1, 5.6, 5.6, "Medium")]
        [DataRow("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H", 10.0, 8.1, 5.6, 5.6, "Medium")]
        [DataRow("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/E:P/RL:W/RC:R/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:C/MC:N/MI:L/MA:H", 5.0, 4.4, 7.4, 7.4, "High")]
        [DataRow("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N/E:P/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:H/MI:H/MA:H", 1.8, 1.7, 9.2, 9.2, "Critical")]
        public void ValidCvss31Vectors(string vector, double baseScore, double temporalScore, double environmentalScore, double overallScore, string severity)
        {
            var cvss = Cvss.Suite.CvssSuite.Create(vector);

            Assert.AreEqual(true, cvss.IsValid());
            Assert.AreEqual(3.1, cvss.Version);
            Assert.AreEqual(baseScore, cvss.BaseScore());
            Assert.AreEqual(temporalScore, cvss.TemporalScore());
            Assert.AreEqual(environmentalScore, cvss.EnvironmentalScore());
            Assert.AreEqual(overallScore, cvss.OverallScore());
            Assert.AreEqual(severity, cvss.Severity());
        }

        [DataTestMethod]
        [DataRow("CVSS:3.1/")]
        [DataRow("CVSS:3.1/AV:L/AC:H/UI:R/S:U/C:L/I:L/A:L")]
        public void InvalidCvss31Vectors(string vector)
        {
            var cvss = Cvss.Suite.CvssSuite.Create(vector);

            Assert.AreEqual(false, cvss.IsValid());
            Assert.AreEqual(3.1, cvss.Version);

            Assert.ThrowsException<ArgumentException>(() => cvss.AvailableMetric());
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
        [DataRow("User Interaction", "Required")]
        [DataRow("Scope", "Unchanged")]
        [DataRow("Confidentiality Impact", "Low")]
        [DataRow("Integrity Impact", "None")]
        [DataRow("Availability Impact", "High")]
        [DataRow("Invalid", "")]
        public void SelectedCvss31Metric(string metric, string selectedMetric)
        {
            var cvss = Cvss.Suite.CvssSuite.Create("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:H");

            Assert.AreEqual(selectedMetric, cvss.SelectedMetric(metric));
        }
    }
}
