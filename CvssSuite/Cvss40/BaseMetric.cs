using System;
using System.Collections.Generic;
using System.Linq;

namespace Cvss.Suite.Cvss40
{
    internal class BaseMetric : MetricGroup
    {
        // https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js
        private readonly Dictionary<string, double> CvssLookup = new Dictionary<string, double> {
            {"000000", 10 }, {"000001", 9.9}, {"000010", 9.8}, {"000011", 9.5}, {"000020", 9.5}, {"000021", 9.2}, {"000100", 10}, {"000101", 9.6}, {"000110", 9.3},
            {"000111", 8.7}, {"000120", 9.1}, {"000121", 8.1}, {"000200", 9.3}, {"000201", 9}, {"000210", 8.9}, {"000211", 8}, {"000220", 8.1}, {"000221", 6.8},
            {"001000", 9.8}, {"001001", 9.5}, {"001010", 9.5}, {"001011", 9.2}, {"001020", 9}, {"001021", 8.4}, {"001100", 9.3}, {"001101", 9.2}, {"001110", 8.9},
            {"001111", 8.1}, {"001120", 8.1}, {"001121", 6.5}, {"001200", 8.8}, {"001201", 8}, {"001210", 7.8}, {"001211", 7}, {"001220", 6.9}, {"001221", 4.8},
            {"002001", 9.2}, {"002011", 8.2}, {"002021", 7.2}, {"002101", 7.9}, {"002111", 6.9}, {"002121", 5}, {"002201", 6.9}, {"002211", 5.5}, {"002221", 2.7},
            {"010000", 9.9}, {"010001", 9.7}, {"010010", 9.5}, {"010011", 9.2}, {"010020", 9.2}, {"010021", 8.5}, {"010100", 9.5}, {"010101", 9.1}, {"010110", 9},
            {"010111", 8.3}, {"010120", 8.4}, {"010121", 7.1}, {"010200", 9.2}, {"010201", 8.1}, {"010210", 8.2}, {"010211", 7.1}, {"010220", 7.2}, {"010221", 5.3},
            {"011000", 9.5}, {"011001", 9.3}, {"011010", 9.2}, {"011011", 8.5}, {"011020", 8.5}, {"011021", 7.3}, {"011100", 9.2}, {"011101", 8.2}, {"011110", 8},
            {"011111", 7.2}, {"011120", 7}, {"011121", 5.9}, {"011200", 8.4}, {"011201", 7}, {"011210", 7.1}, {"011211", 5.2}, {"011220", 5}, {"011221", 3},
            {"012001", 8.6}, {"012011", 7.5}, {"012021", 5.2}, {"012101", 7.1}, {"012111", 5.2}, {"012121", 2.9}, {"012201", 6.3}, {"012211", 2.9}, {"012221", 1.7},
            {"100000", 9.8}, {"100001", 9.5}, {"100010", 9.4}, {"100011", 8.7}, {"100020", 9.1}, {"100021", 8.1}, {"100100", 9.4}, {"100101", 8.9}, {"100110", 8.6},
            {"100111", 7.4}, {"100120", 7.7}, {"100121", 6.4}, {"100200", 8.7}, {"100201", 7.5}, {"100210", 7.4}, {"100211", 6.3}, {"100220", 6.3}, {"100221", 4.9},
            {"101000", 9.4}, {"101001", 8.9}, {"101010", 8.8}, {"101011", 7.7}, {"101020", 7.6}, {"101021", 6.7}, {"101100", 8.6}, {"101101", 7.6}, {"101110", 7.4},
            {"101111", 5.8}, {"101120", 5.9}, {"101121", 5}, {"101200", 7.2}, {"101201", 5.7}, {"101210", 5.7}, {"101211", 5.2}, {"101220", 5.2}, {"101221", 2.5},
            {"102001", 8.3}, {"102011", 7}, {"102021", 5.4}, {"102101", 6.5}, {"102111", 5.8}, {"102121", 2.6}, {"102201", 5.3}, {"102211", 2.1}, {"102221", 1.3},
            {"110000", 9.5}, {"110001", 9}, {"110010", 8.8}, {"110011", 7.6}, {"110020", 7.6}, {"110021", 7}, {"110100", 9}, {"110101", 7.7}, {"110110", 7.5},
            {"110111", 6.2}, {"110120", 6.1}, {"110121", 5.3}, {"110200", 7.7}, {"110201", 6.6}, {"110210", 6.8}, {"110211", 5.9}, {"110220", 5.2}, {"110221", 3},
            {"111000", 8.9}, {"111001", 7.8}, {"111010", 7.6}, {"111011", 6.7}, {"111020", 6.2}, {"111021", 5.8}, {"111100", 7.4}, {"111101", 5.9}, {"111110", 5.7},
            {"111111", 5.7}, {"111120", 4.7}, {"111121", 2.3}, {"111200", 6.1}, {"111201", 5.2}, {"111210", 5.7}, {"111211", 2.9}, {"111220", 2.4}, {"111221", 1.6},
            {"112001", 7.1}, {"112011", 5.9}, {"112021", 3}, {"112101", 5.8}, {"112111", 2.6}, {"112121", 1.5}, {"112201", 2.3}, {"112211", 1.3}, {"112221", 0.6},
            {"200000", 9.3}, {"200001", 8.7}, {"200010", 8.6}, {"200011", 7.2}, {"200020", 7.5}, {"200021", 5.8}, {"200100", 8.6}, {"200101", 7.4}, {"200110", 7.4},
            {"200111", 6.1}, {"200120", 5.6}, {"200121", 3.4}, {"200200", 7}, {"200201", 5.4}, {"200210", 5.2}, {"200211", 4}, {"200220", 4}, {"200221", 2.2},
            {"201000", 8.5}, {"201001", 7.5}, {"201010", 7.4}, {"201011", 5.5}, {"201020", 6.2}, {"201021", 5.1}, {"201100", 7.2}, {"201101", 5.7}, {"201110", 5.5},
            {"201111", 4.1}, {"201120", 4.6}, {"201121", 1.9}, {"201200", 5.3}, {"201201", 3.6}, {"201210", 3.4}, {"201211", 1.9}, {"201220", 1.9}, {"201221", 0.8},
            {"202001", 6.4}, {"202011", 5.1}, {"202021", 2}, {"202101", 4.7}, {"202111", 2.1}, {"202121", 1.1}, {"202201", 2.4}, {"202211", 0.9}, {"202221", 0.4},
            {"210000", 8.8}, {"210001", 7.5}, {"210010", 7.3}, {"210011", 5.3}, {"210020", 6}, {"210021", 5}, {"210100", 7.3}, {"210101", 5.5}, {"210110", 5.9},
            {"210111", 4}, {"210120", 4.1}, {"210121", 2}, {"210200", 5.4}, {"210201", 4.3}, {"210210", 4.5}, {"210211", 2.2}, {"210220", 2}, {"210221", 1.1},
            {"211000", 7.5}, {"211001", 5.5}, {"211010", 5.8}, {"211011", 4.5}, {"211020", 4}, {"211021", 2.1}, {"211100", 6.1}, {"211101", 5.1}, {"211110", 4.8},
            {"211111", 1.8}, {"211120", 2}, {"211121", 0.9}, {"211200", 4.6}, {"211201", 1.8}, {"211210", 1.7}, {"211211", 0.7}, {"211220", 0.8}, {"211221", 0.2},
            {"212001", 5.3}, {"212011", 2.4}, {"212021", 1.4}, {"212101", 2.4}, {"212111", 1.2}, {"212121", 0.5}, {"212201", 1}, {"212211", 0.3}, {"212221", 0.1}
        };

        private readonly int[][][] MaxSeverity = new[] {
            new [] { new[] { 1 }, new[] { 4 }, new[] { 5 } },
            new [] { new[] { 1 }, new[] { 2 } },
            new [] { new[] { 7, 6 }, new[] { 8, 8 }, new[] { -1, 10 } },
            new [] { new[] { 6 }, new[] { 5 }, new[] { 4 } },
            new [] { new[] { 1 }, new[] { 1 }, new[] { 1 } },
        };

        internal BaseMetric(Dictionary<string, string> metrics) : base(metrics)
        {
            // All metrics are used in score calculation, no partial score calculation possible
            AvailableMetrics = Metrics.Base()
                .Concat(Metrics.Threat())
                .Concat(Metrics.Environmental())
                .Concat(Metrics.Supplemental())
                .ToList();

        }

        internal override double Score()
        {
            // The following defines the index of each metric's values.
            // It is used when looking for the highest vector part of the
            // combinations produced by the MacroVector respective highest vectors.
            var AV_levels = new Dictionary<string, double>() { { "N", 0.0 }, { "A", 0.1 }, { "L", 0.2 }, { "P", 0.3 } };
            var PR_levels = new Dictionary<string, double>() { { "N", 0.0 }, { "L", 0.1 }, { "H", 0.2 } };
            var UI_levels = new Dictionary<string, double>() { { "N", 0.0 }, { "P", 0.1 }, { "A", 0.2 } };

            var AC_levels = new Dictionary<string, double>() { { "L", 0.0 }, { "H", 0.1 } };
            var AT_levels = new Dictionary<string, double>() { { "N", 0.0 }, { "P", 0.1 } };

            var VC_levels = new Dictionary<string, double>() { { "H", 0.0 }, { "L", 0.1 }, { "N", 0.2 } };
            var VI_levels = new Dictionary<string, double>() { { "H", 0.0 }, { "L", 0.1 }, { "N", 0.2 } };
            var VA_levels = new Dictionary<string, double>() { { "H", 0.0 }, { "L", 0.1 }, { "N", 0.2 } };

            var SC_levels = new Dictionary<string, double>() { { "H", 0.1 }, { "L", 0.2 }, { "N", 0.3 } };
            var SI_levels = new Dictionary<string, double>() { { "S", 0.0 }, { "H", 0.1 }, { "L", 0.2 }, { "N", 0.3 } };
            var SA_levels = new Dictionary<string, double>() { { "S", 0.0 }, { "H", 0.1 }, { "L", 0.2 }, { "N", 0.3 } };

            var CR_levels = new Dictionary<string, double>() { { "H", 0.0 }, { "M", 0.1 }, { "L", 0.2 } };
            var IR_levels = new Dictionary<string, double>() { { "H", 0.0 }, { "M", 0.1 }, { "L", 0.2 } };
            var AR_levels = new Dictionary<string, double>() { { "H", 0.0 }, { "M", 0.1 }, { "L", 0.2 } };

            var E_levels = new Dictionary<string, double>() { { "U", 0.2 }, { "P", 0.1 }, { "A", 0 } };

            // Exception for no impact on system (shortcut)
            if (new[] {
                "VC", "VI", "VA", "SC", "SI", "SA" }.All((metric) => SelectedValueAbbreviation(metric) == "N"))
            {
                return 0.0;
            }

            var macroVectorResult = GetMacroVector();
            var value = LookupValue(string.Join("", macroVectorResult)).Value;
            var eq1 = macroVectorResult[0];
            var eq2 = macroVectorResult[1];
            var eq3 = macroVectorResult[2];
            var eq4 = macroVectorResult[3];
            var eq5 = macroVectorResult[4];
            var eq6 = macroVectorResult[5];

            // compute next lower macro, it can also not exist
            var eq1NextLowerMacro = string.Join("", new[] { eq1 + 1, eq2, eq3, eq4, eq5, eq6 });
            var eq2NextLowerMacro = string.Join("", new[] { eq1, eq2 + 1, eq3, eq4, eq5, eq6 });

            // eq3 and eq6 are related
            string eq3eq6NextLowerMacro = null;
            string eq3eq6NextLowerMacroLeft = null;
            string eq3eq6NextLowerMacroRight = null;
            if (eq3 == 1 && eq6 == 1)
            {
                // 11 --> 21
                eq3eq6NextLowerMacro = string.Join("", new[] { eq1, eq2, eq3 + 1, eq4, eq5, eq6 });
            }
            else if (eq3 == 0 && eq6 == 1)
            {
                // 01 --> 11
                eq3eq6NextLowerMacro = string.Join("", new[] { eq1, eq2, eq3 + 1, eq4, eq5, eq6 });
            }
            else if (eq3 == 1 && eq6 == 0)
            {
                // 10 --> 11
                eq3eq6NextLowerMacro = string.Join("", new[] { eq1, eq2, eq3, eq4, eq5, eq6 + 1 });
            }
            else if (eq3 == 0 && eq6 == 0)
            {
                // 00 --> 01
                // 00 --> 10
                eq3eq6NextLowerMacroLeft = string.Join("", new[] { eq1, eq2, eq3, eq4, eq5, eq6 + 1 });
                eq3eq6NextLowerMacroRight = string.Join("", new[] { eq1, eq2, eq3 + 1, eq4, eq5, eq6 });
            }
            else
            {
                // 21 --> 32 (do not exist)
                eq3eq6NextLowerMacro = string.Join("", new[] { eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1 });
            }

            var eq4NextLowerMacro = string.Join("", new[] { eq1, eq2, eq3, eq4 + 1, eq5, eq6 });
            var eq5NextLowerMacro = string.Join("", new[] { eq1, eq2, eq3, eq4, eq5 + 1, eq6 });

            // get their score, if the next lower macro score do not exist the result is NaN
            var scoreEq1NextLowerMacro = LookupValue(eq1NextLowerMacro);
            var scoreEq2NextLowerMacro = LookupValue(eq2NextLowerMacro);
            double? scoreEq3eq6NextLowerMacro;
            if (eq3 == 0 && eq6 == 0)
            {
                // multiple path take the one with higher score
                var scoreEq3eq6NextLowerMacroLeft = LookupValue(eq3eq6NextLowerMacroLeft);
                var scoreEq3eq6NextLowerMacroRight = LookupValue(eq3eq6NextLowerMacroRight);

                if (scoreEq3eq6NextLowerMacroLeft > scoreEq3eq6NextLowerMacroRight)
                {
                    scoreEq3eq6NextLowerMacro = scoreEq3eq6NextLowerMacroLeft;
                }
                else
                {
                    scoreEq3eq6NextLowerMacro = scoreEq3eq6NextLowerMacroRight;
                }
            }
            else
            {
                scoreEq3eq6NextLowerMacro = LookupValue(eq3eq6NextLowerMacro);
            }

            var scoreEq4NextLowerMacro = LookupValue(eq4NextLowerMacro);
            var scoreEq5NextLowerMacro = LookupValue(eq5NextLowerMacro);

            //   b. The severity distance of the to-be scored vector from a
            //      highest severity vector in the same MacroVector is determined.
            var eq1Maxes = GetEQMaxes1(macroVectorResult[0]);
            var eq2Maxes = GetEQMaxes2(macroVectorResult[1]);
            var eq3Eq6Maxes = GetEQMaxes36(macroVectorResult[2], macroVectorResult[5]);
            var eq4Maxes = GetEQMaxes4(macroVectorResult[3]);
            var eq5Maxes = GetEQMaxes5(macroVectorResult[4]);

            // compose them
            var maxVectors = new List<string>();
            foreach (var eq1Max in eq1Maxes)
            {
                foreach (var eq2Max in eq2Maxes)
                {
                    foreach (var eq3Eq6Max in eq3Eq6Maxes)
                    {
                        foreach (var eq4Max in eq4Maxes)
                        {
                            foreach (var eq5max in eq5Maxes)
                            {
                                maxVectors.Add(eq1Max + eq2Max + eq3Eq6Max + eq4Max + eq5max);
                            }
                        }
                    }
                }
            }

            // Find the max vector to use i.e. one in the combination of all the highests
            // that is greater or equal (severity distance) than the to-be scored vector.
            var severityDistance = new Dictionary<string, double>()
            {
                { "AV", 0 },
                { "PR", 0 },
                { "UI", 0 },
                { "AC", 0 },
                { "AT", 0 },
                { "VC", 0 },
                { "VI", 0 },
                { "VA", 0 },
                { "SC", 0 },
                { "SI", 0 },
                { "SA", 0 },
                { "CR", 0 },
                { "IR", 0 },
                { "AR", 0 }
            };

            foreach (var maxVector in maxVectors)
            {
                severityDistance["AV"] = AV_levels[SelectedValueAbbreviation("AV")] - AV_levels[ExtractValueMetric("AV", maxVector)];
                severityDistance["PR"] = PR_levels[SelectedValueAbbreviation("PR")] - PR_levels[ExtractValueMetric("PR", maxVector)];
                severityDistance["UI"] = UI_levels[SelectedValueAbbreviation("UI")] - UI_levels[ExtractValueMetric("UI", maxVector)];

                severityDistance["AC"] = AC_levels[SelectedValueAbbreviation("AC")] - AC_levels[ExtractValueMetric("AC", maxVector)];
                severityDistance["AT"] = AT_levels[SelectedValueAbbreviation("AT")] - AT_levels[ExtractValueMetric("AT", maxVector)];

                severityDistance["VC"] = VC_levels[SelectedValueAbbreviation("VC")] - VC_levels[ExtractValueMetric("VC", maxVector)];
                severityDistance["VI"] = VI_levels[SelectedValueAbbreviation("VI")] - VI_levels[ExtractValueMetric("VI", maxVector)];
                severityDistance["VA"] = VA_levels[SelectedValueAbbreviation("VA")] - VA_levels[ExtractValueMetric("VA", maxVector)];

                severityDistance["SC"] = SC_levels[SelectedValueAbbreviation("SC")] - SC_levels[ExtractValueMetric("SC", maxVector)];
                severityDistance["SI"] = SI_levels[SelectedValueAbbreviation("SI")] - SI_levels[ExtractValueMetric("SI", maxVector)];
                severityDistance["SA"] = SA_levels[SelectedValueAbbreviation("SA")] - SA_levels[ExtractValueMetric("SA", maxVector)];

                severityDistance["CR"] = CR_levels[SelectedValueAbbreviation("CR")] - CR_levels[ExtractValueMetric("CR", maxVector)];
                severityDistance["IR"] = IR_levels[SelectedValueAbbreviation("IR")] - IR_levels[ExtractValueMetric("IR", maxVector)];
                severityDistance["AR"] = AR_levels[SelectedValueAbbreviation("AR")] - AR_levels[ExtractValueMetric("AR", maxVector)];

                // if any is less than zero this is not the right max
                if (severityDistance.Values.Any((met) => met < 0))
                {
                    continue;
                }

                // if multiple maxes exist to reach it it is enough the first one
                break;
            }

            var currentSeverityDistanceEq1 = severityDistance["AV"] + severityDistance["PR"] + severityDistance["UI"];
            var currentSeverityDistanceEq2 = severityDistance["AC"] + severityDistance["AT"];
            var currentSeverityDistanceEq3eq6 = severityDistance["VC"] + severityDistance["VI"] + severityDistance["VA"] + severityDistance["CR"] + severityDistance["IR"] + severityDistance["AR"];
            var currentSeverityDistanceEq4 = severityDistance["SC"] + severityDistance["SI"] + severityDistance["SA"];

            var step = 0.1;

            // if the next lower macro score do not exist the result is Nan
            // Rename to maximal scoring difference (aka MSD)
            var availableDistanceEq1 = value - scoreEq1NextLowerMacro;
            var availableDistanceEq2 = value - scoreEq2NextLowerMacro;
            var availableDistanceEq3eq6 = value - scoreEq3eq6NextLowerMacro;
            var availableDistanceEq4 = value - scoreEq4NextLowerMacro;
            var availableDistanceEq5 = value - scoreEq5NextLowerMacro;

            var percentToNextEq1Severity = 0.0;
            var percentToNextEq2Severity = 0.0;
            var percentToNextEq3eq6Severity = 0.0;
            var percentToNextEq4Severity = 0.0;
            var percentToNextEq5Severity = 0.0;

            // some of them do not exist, we will find them by retrieving the score. If score null then do not exist
            var nExistingLower = 0;

            var normalizedSeverityEq1 = 0.0;
            var normalizedSeverityEq2 = 0.0;
            var normalizedSeverityEq3eq6 = 0.0;
            var normalizedSeverityEq4 = 0.0;
            var normalizedSeverityEq5 = 0.0;

            // multiply by step because distance is pure
            var maxSeverityEq1 = MaxSeverity[0][eq1][0] * step;
            var maxSeverityEq2 = MaxSeverity[1][eq2][0] * step;
            var maxSeverityEq3eq6 = MaxSeverity[2][eq3][eq6] * step;
            var maxSeverityEq4 = MaxSeverity[3][eq4][0] * step;

            //   c. The proportion of the distance is determined by dividing
            //      the severity distance of the to-be-scored vector by the depth
            //      of the MacroVector.
            //   d. The maximal scoring difference is multiplied by the proportion of
            //      distance.
            if (availableDistanceEq1.HasValue)
            {
                nExistingLower++;
                percentToNextEq1Severity = (currentSeverityDistanceEq1) / maxSeverityEq1;
                normalizedSeverityEq1 = availableDistanceEq1.Value * percentToNextEq1Severity;
            }

            if (availableDistanceEq2.HasValue)
            {
                nExistingLower++;
                percentToNextEq2Severity = (currentSeverityDistanceEq2) / maxSeverityEq2;
                normalizedSeverityEq2 = availableDistanceEq2.Value * percentToNextEq2Severity;
            }

            if (availableDistanceEq3eq6.HasValue)
            {
                nExistingLower++;
                percentToNextEq3eq6Severity = (currentSeverityDistanceEq3eq6) / maxSeverityEq3eq6;
                normalizedSeverityEq3eq6 = availableDistanceEq3eq6.Value * percentToNextEq3eq6Severity;
            }

            if (availableDistanceEq4.HasValue)
            {
                nExistingLower++;
                percentToNextEq4Severity = (currentSeverityDistanceEq4) / maxSeverityEq4;
                normalizedSeverityEq4 = availableDistanceEq4.Value * percentToNextEq4Severity;
            }

            if (availableDistanceEq5.HasValue)
            {
                // for eq5 is always 0 the percentage
                nExistingLower++;
                percentToNextEq5Severity = 0;
                normalizedSeverityEq5 = availableDistanceEq5.Value * percentToNextEq5Severity;
            }

            // 2. The mean of the above computed proportional distances is computed.
            double meanDistance;
            if (nExistingLower == 0)
            {
                meanDistance = 0;
            }
            else
            { 
                // sometimes we need to go up but there is nothing there, or down but there is nothing there so it's a change of 0.
                meanDistance = (normalizedSeverityEq1 + normalizedSeverityEq2 + normalizedSeverityEq3eq6 + normalizedSeverityEq4 + normalizedSeverityEq5) / nExistingLower;
            }

            // 3. The score of the vector is the score of the MacroVector
            //    (i.e. the score of the highest severity vector) minus the mean
            //    distance so computed. This score is rounded to one decimal place.
            value -= meanDistance;
            if (value < 0)
            {
                value = 0.0;
            }
            if (value > 10)
            {
                value = 10.0;
            }

            return Math.Round(value * 10) / 10;
        }

        private string SelectedValueAbbreviation(string metricAbbrev)
        {
            try
            {
                var selectedValueAbbrev = ExtractedMetrics.ContainsKey(metricAbbrev) ? ExtractedMetrics[metricAbbrev] : "X";

                // If E=X it will default to the worst case i.e. E=A
                if (metricAbbrev == "E" && selectedValueAbbrev == "X")
                {
                    return "A";
                }
                // If CR=X, IR=X or AR=X they will default to the worst case i.e. CR=H, IR=H and AR=H
                if (metricAbbrev == "CR" && selectedValueAbbrev == "X")
                {
                    return "H";
                }
                // IR:X is the same as IR:H
                if (metricAbbrev == "IR" && selectedValueAbbrev == "X")
                {
                    return "H";
                }
                // AR:X is the same as AR:H
                if (metricAbbrev == "AR" && selectedValueAbbrev == "X")
                {
                    return "H";
                }

                // All other environmental metrics just overwrite base score values,
                // so if they’re not defined just use the base score value.
                if (ExtractedMetrics.ContainsKey("M" + metricAbbrev))
                {
                    var modifiedSelected = ExtractedMetrics["M" + metricAbbrev];
                    if (modifiedSelected != "X")
                    {
                        return modifiedSelected;
                    }
                }

                return selectedValueAbbrev;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        }

        private int[] GetMacroVector()
        {
            var macroVector = new int[6];

            // EQ1: 0-AV:N and PR:N and UI:N
            //      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
            //      2-AV:P or not(AV:N or PR:N or UI:N)

            if (SelectedValueAbbreviation("AV") == "N" && SelectedValueAbbreviation("PR") == "N" && SelectedValueAbbreviation("UI") == "N")
            {
                macroVector[0] = 0;
            }
            else if ((SelectedValueAbbreviation("AV") == "N" || SelectedValueAbbreviation("PR") == "N" || SelectedValueAbbreviation("UI") == "N")
                && !(SelectedValueAbbreviation("AV") == "N" && SelectedValueAbbreviation("PR") == "N" && SelectedValueAbbreviation("UI") == "N")
                && !(SelectedValueAbbreviation("AV") == "P"))
            {
                macroVector[0] = 1;
            }
            else if (SelectedValueAbbreviation("AV") == "P"
                || !(SelectedValueAbbreviation("AV") == "N" || SelectedValueAbbreviation("PR") == "N" || SelectedValueAbbreviation("UI") == "N"))
            {
                macroVector[0] = 2;
            }

            // EQ2: 0-(AC:L and AT:N)
            //      1-(not(AC:L and AT:N))

            if (SelectedValueAbbreviation("AC") == "L" && SelectedValueAbbreviation("AT") == "N")
            {
                macroVector[1] = 0;
            }
            else if (!(SelectedValueAbbreviation("AC") == "L" && SelectedValueAbbreviation("AT") == "N"))
            {
                macroVector[1] = 1;
            }

            // EQ3: 0-(VC:H and VI:H)
            //      1-(not(VC:H and VI:H) and (VC:H or VI:H or VA:H))
            //      2-not (VC:H or VI:H or VA:H)
            if (SelectedValueAbbreviation("VC") == "H" && SelectedValueAbbreviation("VI") == "H")
            {
                macroVector[2] = 0;
            }
            else if (!(SelectedValueAbbreviation("VC") == "H" && SelectedValueAbbreviation("VI") == "H")
                && (SelectedValueAbbreviation("VC") == "H" || SelectedValueAbbreviation("VI") == "H" || SelectedValueAbbreviation("VA") == "H"))
            {
                macroVector[2] = 1;
            }
            else if (!(SelectedValueAbbreviation("VC") == "H" || SelectedValueAbbreviation("VI") == "H" || SelectedValueAbbreviation("VA") == "H"))
            {
                macroVector[2] = 2;
            }

            // EQ4: 0-(MSI:S or MSA:S)
            //      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
            //      2-not (MSI:S or MSA:S) and not (SC:H or SI:H or SA:H)

            if (SelectedValueAbbreviation("MSI") == "S" || SelectedValueAbbreviation("MSA") == "S")
            {
                macroVector[3] = 0;
            }
            else if (!(SelectedValueAbbreviation("MSI") == "S" || SelectedValueAbbreviation("MSA") == "S") &&
                (SelectedValueAbbreviation("SC") == "H" || SelectedValueAbbreviation("SI") == "H" || SelectedValueAbbreviation("SA") == "H"))
            {
                macroVector[3] = 1;
            }
            else if (!(SelectedValueAbbreviation("MSI") == "S" || SelectedValueAbbreviation("MSA") == "S") &&
                !((SelectedValueAbbreviation("SC") == "H" || SelectedValueAbbreviation("SI") == "H" || SelectedValueAbbreviation("SA") == "H")))
            {
                macroVector[3] = 2;
            }

            // EQ5: 0-E:A
            //      1-E:P
            //      2-E:U

            if (SelectedValueAbbreviation("E") == "A")
            {
                macroVector[4] = 0;
            }
            else if (SelectedValueAbbreviation("E") == "P")
            {
                macroVector[4] = 1;
            }
            else if (SelectedValueAbbreviation("E") == "U")
            {
                macroVector[4] = 2;
            }

            // EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)
            //      1-not[(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)]

            if ((SelectedValueAbbreviation("CR") == "H" && SelectedValueAbbreviation("VC") == "H")
                || (SelectedValueAbbreviation("IR") == "H" && SelectedValueAbbreviation("VI") == "H")
                || (SelectedValueAbbreviation("AR") == "H" && SelectedValueAbbreviation("VA") == "H"))
            {
                macroVector[5] = 0;
            }
            else if (!((SelectedValueAbbreviation("CR") == "H" && SelectedValueAbbreviation("VC") == "H")
                || (SelectedValueAbbreviation("IR") == "H" && SelectedValueAbbreviation("VI") == "H")
                || (SelectedValueAbbreviation("AR") == "H" && SelectedValueAbbreviation("VA") == "H")))
            {
                macroVector[5] = 1;
            }

            return macroVector;
        }


        private string[] GetEQMaxes1(int value)
        {
            var maxComposed = new[] {
                new[] {"AV:N/PR:N/UI:N/" },
                new[] {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
                new[] {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/" }
            };

            return maxComposed[value];
        }

        private string[] GetEQMaxes2(int value)
        {
            var maxComposed = new[] {
                new[] {"AC:L/AT:N/" },
                new[] {"AC:H/AT:N/", "AC:L/AT:P/" }
            };

            return maxComposed[value];
        }

        private string[] GetEQMaxes36(int value3, int value6)
        {
            var maxComposed = new[] {
                new[] { new[] { "VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/" }, new[] { "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/" } },
                new[] { new[] { "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/" }, new[] { "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/" } },
                new[] { new string[0], new[] { "VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/" } },
            };

            return maxComposed[value3][value6];
        }

        private string[] GetEQMaxes4(int value)
        {
            var maxComposed = new[] {
                new[] { "SC:H/SI:S/SA:S/" },
                new[] { "SC:H/SI:H/SA:H/" },
                new[] { "SC:L/SI:L/SA:L/" }
            };

            return maxComposed[value];
        }

        private string[] GetEQMaxes5(int value)
        {
            var maxComposed = new[] {
                new[] { "E:A/" },
                new[] { "E:P/" },
                new[] { "E:U/" },
            };

            return maxComposed[value];
        }

        private string ExtractValueMetric(string metric, string str)
        {
            // indexOf gives first index of the metric, we then need to go over its size
            var extracted = str.Substring(str.IndexOf(metric) + metric.Length + 1);
            string metricVal;

            // remove what follow
            if (extracted.IndexOf('/') > 0)
            {
                metricVal = extracted.Substring(0, extracted.IndexOf('/'));
            }
            else
            {
                // case where it is the last metric so no ending /
                metricVal = extracted;
            }

            return metricVal;
        }

        private double? LookupValue(string value)
        {
            if (!CvssLookup.ContainsKey(value))
            {
                return null;
            }

            return CvssLookup[value];
        }
    }
}
