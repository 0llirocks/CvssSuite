using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Cvss.Suite.Tests
{
    [TestClass]
    public class CvssSuite
    {
        [DataTestMethod]
        [DataRow("Not a valid vector!")]
        [DataRow(null)]
        public void InvalidCvssVectors(string vector)
        {
            var cvss = Cvss.Suite.CvssSuite.Create(vector);

            Assert.AreEqual(false, cvss.IsValid());
            Assert.AreEqual(0, cvss.Version);
        }

    }
}
