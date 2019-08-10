using System;
using Cvss.Suite;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cvss.Suite.Tests.Cvss2
{
    [TestClass]
    public class Cvss
    {

        [DataTestMethod]
        //Base Score
        [DataRow("AV:L/AC:H/Au:M/C:P/I:N/A:N", 0.8, 0.8, 0.8, 0.8, "Low")]
        [DataRow("AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2, 6.2, 6.2, 6.2, "Medium")]
        [DataRow("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, 7.5, 7.5, 7.5, "High")]
        [DataRow("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0, 10.0, 10.0, 10.0, "Critical")]

        //Base Score + Temporal Score
        [DataRow("AV:L/AC:H/Au:M/C:P/I:N/A:N/E:U/RL:OF/RC:UC", 0.8, 0.5, 0.5, 0.5, "Low")]
        [DataRow("AV:N/AC:L/Au:N/C:P/I:P/A:P/E:U/RL:OF/RC:C", 7.5, 5.5, 5.5, 5.5, "Medium")]
        [DataRow("AV:N/AC:L/Au:S/C:P/I:C/A:P/E:H/RL:W/RC:C", 8.0, 7.6, 7.6, 7.6, "High")]
        [DataRow("AV:N/AC:L/Au:N/C:P/I:C/A:P/E:H/RL:U/RC:C", 9.0, 9.0, 9.0, 9.0, "Critical")]

        //Base Score + Environmental Score
        [DataRow("AV:N/AC:M/Au:M/C:C/I:P/A:N/CDP:N/TD:M/CR:L/IR:M/AR:M", 6.4, 6.4, 3.4, 3.4, "Low")]
        [DataRow("AV:A/AC:M/Au:S/C:P/I:P/A:P/CDP:L/TD:M/CR:M/IR:M/AR:M", 4.9, 4.9, 4.1, 4.1, "Medium")]
        [DataRow("AV:L/AC:M/Au:N/C:C/I:P/A:C/CDP:MH/TD:H/CR:H/IR:H/AR:H", 6.6, 6.6, 8.1, 8.1, "High")]
        [DataRow("AV:N/AC:L/Au:M/C:C/I:P/A:N/CDP:H/TD:H/CR:H/IR:H/AR:H", 6.8, 6.8, 9.2, 9.2, "Critical")]

        //Base Score + Temporal Score + Environmental Score
        [DataRow("AV:L/AC:H/Au:M/C:P/I:N/A:N/E:U/RL:OF/RC:UC/CDP:L/TD:L/CR:L/IR:L/AR:L", 0.8, 0.5, 0.2, 0.2, "Low")]
        [DataRow("AV:A/AC:M/Au:M/C:P/I:N/A:C/E:F/RL:U/RC:UR/CDP:MH/TD:M/CR:L/IR:M/AR:H", 5.4, 4.9, 5.8, 5.8, "Medium")]
        [DataRow("AV:A/AC:L/Au:N/C:C/I:P/A:P/E:H/RL:U/RC:C/CDP:L/TD:H/CR:M/IR:H/AR:H", 7.3, 7.3, 8.0, 8.0, "High")]
        [DataRow("AV:N/AC:L/Au:N/C:C/I:P/A:P/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H", 9.0, 9.0, 10.0, 10.0, "Critical")]
        public void ValidCvss2Vectors(string vector, double baseScore, double temporalScore, double environmentalScore, double overallScore, string severity)
        {
            var cvss = CvssSuite.Create(vector);

            Assert.AreEqual(true, cvss.IsValid());
            Assert.AreEqual(2, cvss.Version);
            Assert.AreEqual(baseScore, cvss.BaseScore());
            Assert.AreEqual(temporalScore, cvss.TemporalScore());
            Assert.AreEqual(environmentalScore, cvss.EnvironmentalScore());
            Assert.AreEqual(overallScore, cvss.OverallScore());
            Assert.AreEqual(severity, cvss.Severity());
        }

        [DataTestMethod]
        [DataRow("")]
        public void InvalidCvss2VectorsWithVersion()
        {

        }

        [DataTestMethod]
        [DataRow("")]
        public void InvalidCvss2Vectors()
        {

        }
    }
}
