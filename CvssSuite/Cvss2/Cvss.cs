using System.Text.RegularExpressions;

namespace Cvss.Suite.Cvss2
{
    /// <summary>
    /// Represents a CVSS v2 object.
    /// </summary>
    public class Cvss : CvssBase
    {
        internal Cvss(string vector, double version) : base(vector, version)
        {
            if (!IsValid()) return;
            
            ExtractedMetrics = ExtractMetrics();

            BaseMetric = new BaseMetric(ExtractedMetrics);
            TemporalMetric = new TemporalMetric(ExtractedMetrics, BaseMetric.Score());
            EnvironmentalMetric = new EnvironmentalMetric(ExtractedMetrics);
        }

        /// <summary>
        /// Returns whether the CVSS object is valid or not.
        /// </summary>
        public override bool IsValid()
        {
            string base_pattern = @"^AV:[NAL]\/AC:[LHM]\/Au:[MSN]\/C:[NPC]\/I:[NPC]\/A:[NPC]";
            string temporal_pattern = @"\/E:(U|POC|F|H|ND)\/RL:(OF|TF|W|U|ND)\/RC:(UC|UR|C|ND)";
            string environmental_pattern = @"\/CDP:(N|L|LM|MH|H|ND)\/TD:(N|L|M|H|ND)\/CR:(L|M|H|ND)\/IR:(L|M|H|ND)\/AR:(L|M|H|ND)";
            
            if (Regex.IsMatch(Vector, base_pattern + "$")) return true;
            if (Regex.IsMatch(Vector, base_pattern + temporal_pattern + "$")) return true;
            if (Regex.IsMatch(Vector, base_pattern + environmental_pattern + "$")) return true;
            if (Regex.IsMatch(Vector, base_pattern + temporal_pattern + environmental_pattern + "$")) return true;
            return false;
        }
    }
}
