/* global console */

class DatasetReporter {
  onRunComplete(_contexts, results) {
    const totalMs = results.startTime
      ? Date.now() - results.startTime
      : undefined;
    const suitesPassed = results.numPassedTestSuites;
    const suitesFailed = results.numFailedTestSuites;
    const testsPassed = results.numPassedTests;
    const testsFailed = results.numFailedTests;
    const testsPending = results.numPendingTests;

    const allAssertions = [];
    for (const tr of results.testResults) {
      for (const ar of tr.testResults) {
        allAssertions.push({
          fullName: ar.fullName,
          duration: ar.duration ?? 0,
        });
      }
    }

    allAssertions.sort((a, b) => b.duration - a.duration);
    const slowest = allAssertions.slice(0, 5).filter((a) => a.duration > 0);

    const lines = [];
    lines.push("");
    lines.push("Dataset Summary");
    lines.push(
      `Suites: ${suitesPassed} passed, ${suitesFailed} failed | Tests: ${testsPassed} passed, ${testsFailed} failed, ${testsPending} skipped`,
    );
    if (typeof totalMs === "number") {
      lines.push(`Duration: ${(totalMs / 1000).toFixed(2)}s`);
    }
    if (slowest.length > 0) {
      lines.push("Slowest tests:");
      for (const s of slowest) {
        lines.push(`- ${s.duration}ms  ${s.fullName}`);
      }
    }
    lines.push("");

    console.log(lines.join("\n"));
  }
}

module.exports = DatasetReporter;
