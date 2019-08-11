using System;
using System.Collections.Generic;

namespace Cvss.Suite
{
    /// <summary>
    /// Represents a CVSS obejct.
    /// </summary>
    public abstract class CvssBase
    {

        /// <summary>
        /// Returns the vector of the CVSS object.
        /// </summary>
        public readonly string Vector;

        /// <summary>
        /// Returns the version of the CVSS object.
        /// </summary>
        public readonly double Version;

        /// <summary>
        /// Returns the base score of the CVSS object.
        /// </summary>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public double BaseScore()
        {
            if (!IsValid()) throw new ArgumentException();

            return BaseMetric.Score();
        }

        /// <summary>
        /// Returns the temporal score of the CVSS object.
        /// </summary>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public double TemporalScore()
        {
            if (!IsValid()) throw new ArgumentException();

            return TemporalMetric.Score();
        }

        /// <summary>
        /// Returns the environmental score of the CVSS object.
        /// </summary>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public double EnvironmentalScore()
        {
            if (!IsValid()) throw new ArgumentException();

            return EnvironmentalMetric.Score();
        }

        /// <summary>
        /// Returns the overall score of the CVSS object.
        /// </summary>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public double OverallScore()
        {
            if (!IsValid()) throw new ArgumentException();

            if (EnvironmentalScore() > 0) return EnvironmentalScore();
            if (TemporalScore() > 0) return TemporalScore();
            return BaseScore();
        }

        /// <summary>
        /// Returns the severity of the CVSS object.
        /// </summary>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public string Severity()
        {
            if (!IsValid()) throw new ArgumentException();

            var score = OverallScore();

            if (0.0 == score) return "None";
            else if (score <= 3.9) return "Low";
            else if (score <= 6.9) return "Medium";
            else if (score <= 8.9) return "High";
            else if (score <= 10.0) return "Critical";
            else return "None";
        }

        /// <summary>
        /// Returns whether the CVSS object is valid or not.
        /// </summary>
        public abstract bool IsValid();

        /// <summary>
        /// Returns the selected value for a metric.
        /// </summary>
        /// <returns>
        /// Returns the selected value or empty string if metric is not found.
        /// </returns>
        /// <example>
        /// <code>
        /// var selected = cvss.SelectedValue("Access Vector");
        /// returns "Network"
        /// </code>
        /// </example>
        /// <param name="metric">A valid metric e.g. "Access Vector", "Authentication", "Attack Vector".</param>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public string SelectedMetric(string metric)
        {
            if (!IsValid()) throw new ArgumentException();

            if (!String.IsNullOrEmpty(BaseMetric.SelectedValue(metric))) return BaseMetric.SelectedValue(metric);
            if (!String.IsNullOrEmpty(TemporalMetric.SelectedValue(metric))) return TemporalMetric.SelectedValue(metric);
            if (!String.IsNullOrEmpty(EnvironmentalMetric.SelectedValue(metric))) return EnvironmentalMetric.SelectedValue(metric);
            return "";
        }

        /// <summary>
        /// Returns the selected value for a metric.
        /// </summary>
        /// <returns>
        /// Returns the selected value or empty string if metric is not found.
        /// </returns>
        /// <example>
        /// <code>
        /// var selected = cvss.SelectedValue(Cvss2.Metrics.AccessVector");
        /// returns "Network"
        /// </code>
        /// </example>
        /// <param name="metric">A valid metric e.g. <see cref="Cvss2.Metrics.AccessVector"/>, <see cref="Cvss30.Metrics.IntegrityImpact"/>, <see cref="Cvss31.Metrics.ModifiedAttackVector"/>.</param>
        /// <exception cref="System.ArgumentException">Thrown when vector is not valid.</exception>
        public string SelectedMetric(Metric metric)
        {
            return SelectedMetric(metric.Name);
        }

        internal CvssBase(string vector, double version)
        {
            Vector = vector;
            Version = version;
        }

        internal MetricGroup BaseMetric;

        internal MetricGroup TemporalMetric;

        internal MetricGroup EnvironmentalMetric;

        protected Dictionary<string, string> ExtractedMetrics;

        protected Dictionary<string, string> ExtractMetrics()
        {
            if (!IsValid()) throw new ArgumentException();

            var dict = new Dictionary<string, string>();

            var metrics = Vector.Split('/');

            foreach (var metric in metrics)
            {
                var abbreviation = metric.Split(':')[0];
                var value = metric.Split(':')[1];

                if (abbreviation == "CVSS") continue;

                dict.Add(abbreviation, value);
            }

            return dict;
        }
    }
}
