import {
  assessAzureReadiness,
  createAzureApplicationInsightsSink,
  createTelemetryRecorder,
  defaultPolicy,
  defaultTelemetryConfig,
  InMemoryTelemetrySink,
  piiText,
} from "../src";

async function main(): Promise<void> {
  const audit = new InMemoryTelemetrySink();
  const logs = new InMemoryTelemetrySink();
  const emitted: string[] = [];

  const azureSink = createAzureApplicationInsightsSink(
    {
      trackEvent: () => {
        throw new Error("Dry-run should prevent network calls");
      },
    },
    {
      dryRun: true,
      onEmit: (event) => emitted.push(event.name),
    },
  );

  const recorder = createTelemetryRecorder(
    {
      ...defaultTelemetryConfig("staging"),
      logSamplingRate: 1,
    },
    {
      auditSinks: [audit],
      logSinks: [logs, azureSink],
      deps: {
        random: () => 0,
      },
    },
  );

  await recorder.recordPolicyDecision(
    defaultPolicy(),
    "log",
    { user: piiText("user@example.com") },
    { traceId: "smoke-trace-1", sourceIp: "203.0.113.1" },
  );

  recorder.enableIncidentMode({ durationMs: 60_000, reason: "smoke" });

  await recorder.recordSecurityEvent({
    name: "auth.failed",
    severity: "high",
    traceId: "smoke-trace-2",
    details: { password: "plaintext" },
  });

  const readiness = assessAzureReadiness({
    appInsightsConnectionString: "InstrumentationKey=00000000-0000-0000-0000-000000000000",
    logAnalyticsWorkspaceId: "workspace-id",
    dataCollectionEndpoint: "https://example.ingest.monitor.azure.com",
    dataCollectionRuleId: "dcr-id",
    immutableArchiveEnabled: true,
    hotRetentionDays: 30,
    archiveRetentionDays: 180,
    alertsConfigured: true,
    dynamicConfigEnabled: true,
  });

  const output = {
    mode: recorder.getMode(),
    auditEvents: audit.events.length,
    logEvents: logs.events.length,
    azureDryRunEvents: emitted.length,
    readiness,
  };

  console.log(JSON.stringify(output, null, 2));
}

void main();
