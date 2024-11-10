# CvssSuite for .NET

[![NuGet Package Version](http://img.shields.io/nuget/v/CvssSuite.svg)](https://www.nuget.org/packages/CvssSuite)
[![Cvss Support](https://img.shields.io/badge/CVSS-v2-brightgreen.svg)](https://www.first.org/cvss/v2/guide)
[![Cvss Support](https://img.shields.io/badge/CVSS-v3.0-brightgreen.svg)](https://www.first.org/cvss/v3.0/user-guide)
[![Cvss Support](https://img.shields.io/badge/CVSS-v3.1-brightgreen.svg)](https://www.first.org/cvss/v3.1/user-guide)
[![Cvss Support](https://img.shields.io/badge/CVSS-v4.0-brightgreen.svg)](https://www.first.org/cvss/v4.0/user-guide)

This NuGet package helps you to process the vector of the [**Common Vulnerability Scoring System**](https://www.first.org/cvss/specification-document).
Besides calculating the Base, Temporal and Environmental Score, you are able to extract the selected option.

## Installation

The best and easiest way to add the CvssSuite to your .NET project is to use the NuGet package manager.

### With Visual Studio IDE
From within Visual Studio, you can use the NuGet GUI to search for and install the CvssSuite NuGet package. Or, as a shortcut, simply type the following command into the Package Manager Console:

    Install-Package CvssSuite

### With .NET Core Command Line Tools
If you are building with the .NET Core command line tools, then you can run the following command from within your project directory:

    dotnet add package CvssSuite

## Usage

```cs
using System;
using Cvss.Suite;

namespace CvssSuiteNugetPackageTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var cvss_v30 = CvssSuite.Create("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H");
            var vector = cvss_v30.Vector;       // "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L/CR:L/IR:M/AR:H/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:N/MI:L/MA:H"
            var version = cvss_v30.Version;     // 3.0
            var valid = cvss_v30.IsValid();     // true
            var severity = cvss_v30.Severity(); // "High"

            var cvss_v31 = CvssSuite.Create("CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U");
            vector = cvss_v31.Vector;           // "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:H/E:H/RL:U/RC:U"
            version = cvss_v31.Version;         // 3.1
            valid = cvss_v31.IsValid();         // true
            severity = cvss_v31.Severity();     // "Medium"

            var cvss_v2 = CvssSuite.Create("AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M");
            vector = cvss_v2.Vector;            // "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:POC/RL:TF/RC:UC/CDP:L/TD:M/CR:M/IR:M/AR:M"
            version = cvss_v2.Version;          // 2
            valid = cvss_v2.IsValid();          // true
            severity = cvss_v2.Severity();      // "Low"
            
            // Scores
            var baseScore = cvss_v2.BaseScore();                    // 4.9
            var temporalScore = cvss_v2.TemporalScore();            // 3.6
            var environmentalScore = cvss_v2.EnvironmentalScore();  // 3.2
            var overallScore = cvss_v2.OverallScore();              // 3.2

            // Selected metric
            var accessVector_1 = cvss_v2.SelectedMetric("Access Vector");                         // "Adjacent Network"
            var accessVector_2 = cvss_v2.SelectedMetric(Cvss.Suite.Cvss2.Metrics.AccessVector);   // "Adjacent Network"

            var remediationLevel_1 = cvss_v2.SelectedMetric("Remediation Level");                       // "Temporary Fix"
            var remediationLevel_2 = cvss_v2.SelectedMetric(Cvss.Suite.Cvss2.Metrics.RemediationLevel); // "Temporary Fix"

            var cvss_v2_metrics = Cvss.Suite.Cvss2.Metrics.ToList();            // Returns a list with all CVSS v2 metrics.
            var cvss_v2_temporalMetrics = Cvss.Suite.Cvss2.Metrics.Temporal();  // Returns a list with all CVSS v2 temporal metrics.

            var cvss_v30_metrics = Cvss.Suite.Cvss30.Metrics.ToList();                      // Returns a list with all CVSS v3.0 metrics.
            var cvss_v30_environmentalMetrics = Cvss.Suite.Cvss30.Metrics.Environmental();  // Returns a list with all CVSS v3.0 environmental metrics.

            // Exceptions
            var invalidVector = CvssSuite.Create("random string or empty string");
            valid = invalidVector.IsValid();        // false
            version = invalidVector.Version;        // 0
            baseScore = invalidVector.BaseScore();  // will throw System.ArgumentException

            invalidVector = CvssSuite.Create("AV:N/AC:P/C:P/AV:U/RL:OF/RC:C"); // invalid vector, authentication is missing
            valid = invalidVector.IsValid();        // false
            version = invalidVector.Version;        // 2
            baseScore = invalidVector.BaseScore();  // will throw System.ArgumentException
        }
    }
}
```

## Known Issues

Currently it is not possible to leave an attribute blank instead of ND/X. If you don't have a value for an attribute, please use ND/X instead.

There is a possibility of implementations generating different scores (+/- 0,1) due to small floating-point inaccuracies. This can happen due to differences in floating point arithmetic between different languages and hardware platforms.

## Changelog

[Click here to see all changes.](https://github.com/0llirocks/CvssSuite/blob/master/CHANGES.md)

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/0llirocks/CvssSuite](https://github.com/0llirocks/CvssSuite). This project is intended to be a safe, welcoming space for collaboration.

## References
[CvssSuite for Ruby](https://cvss-suite.0lli.rocks)
