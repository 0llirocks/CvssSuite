using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace Cvss.Suite.Cvss31
{
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

        public override bool IsValid()
        {
            string base_pattern = @"^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[UNLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]";
            string temporal_pattern = @"\/E:[XUPFH]\/RL:[XOTWU]\/RC:[XURC]";
            string environmental_pattern = @"\/CR:[XLMH]\/IR:[XLMH]\/AR:[XLMH]\/MAV:[XNALP]\/MAC:[XLH]\/MPR:[XUNLH]\/MUI:[XNR]\/MS:[XUC]\/MC:[XNLH]\/MI:[XNLH]\/MA:[XNLH]";
            
            if (Regex.IsMatch(Vector, base_pattern + "$")) return true;
            if (Regex.IsMatch(Vector, base_pattern + temporal_pattern + "$")) return true;
            if (Regex.IsMatch(Vector, base_pattern + environmental_pattern + "$")) return true;
            if (Regex.IsMatch(Vector, base_pattern + temporal_pattern + environmental_pattern + "$")) return true;
            return false;
        }
    }
}
