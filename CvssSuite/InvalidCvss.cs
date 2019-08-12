namespace Cvss.Suite
{
    /// <summary>
    /// Represents an invalid CVSS obejct.
    /// </summary>
    public class InvalidCvss : CvssBase
    {
        internal InvalidCvss(string vector) : base(vector, 0)
        {
        }

        /// <summary>
        /// Returns always false.
        /// </summary>
        public override bool IsValid()
        {
            return false;
        }
    }
}
