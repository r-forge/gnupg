#! /usr/bin/Rscript
require(svUnit)  # Needed if run from R CMD BATCH
require(gnupg)
unlink("report.xml")  # Make sure we generate a new report
mypkgSuite <- svSuiteList("gnupg", dirs="../../pkg/inst/unitTest")  # List all our test suites
runTest(mypkgSuite, name = "gnupg")  # Run them...
protocol(Log(), type = "junit", file = "report.xml")  # ... and write report
