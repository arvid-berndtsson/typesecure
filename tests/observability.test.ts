/**
 * @jest-environment node
 */
import {
  assessAzureReadiness,
  buildIncidentForensicsSummary,
  createAzureApplicationInsightsSink,
  createTelemetryRecorder,
  defaultPolicy,
  detectTelemetryAlerts,
  defaultTelemetryConfig,
  InMemoryTelemetrySink,
  piiText,
  secretText,
  telemetryConfigFromEnv,
  type AzureAppInsightsTrackEventInput,
  type DataClassification,
  type TelemetryEvent,
  type TelemetrySink,
} from "../src";

describe("Observability", () => {
  test("production defaults to detailed logging while non-production defaults to minimal", () => {
    const prod = defaultTelemetryConfig("production");
    const staging = defaultTelemetryConfig("staging");

    expect(prod.loggingEnabled).toBe(true);
    expect(staging.loggingEnabled).toBe(false);
    expect(prod.minimalAuditEnabled).toBe(true);
    expect(staging.minimalAuditEnabled).toBe(true);
  });

  test("staging writes minimal audit but no detailed payload when logging is disabled", async () => {
    const config = {
      ...defaultTelemetryConfig("staging"),
      logSamplingRate: 1,
    };
    const auditSink = new InMemoryTelemetrySink();
    const logSink = new InMemoryTelemetrySink();

    const recorder = createTelemetryRecorder(config, {
      auditSinks: [auditSink],
      logSinks: [logSink],
    });

    await recorder.recordPolicyDecision(
      defaultPolicy(),
      "log",
      { user: piiText("user@example.com") },
      { traceId: "trace-1", sourceIp: "203.0.113.8", actorId: "user-1" },
    );

    expect(auditSink.events).toHaveLength(1);
    expect(logSink.events).toHaveLength(0);
    expect(auditSink.events[0]).toMatchObject({
      eventType: "policy.decision",
      mode: "minimal",
      traceId: "trace-1",
      sourceIp: "203.0.113.8",
      actorId: "user-1",
    });
  });

  test("incident mode escalates detailed logging and redacts payload", async () => {
    const config = {
      ...defaultTelemetryConfig("staging"),
      logSamplingRate: 1,
    };
    const auditSink = new InMemoryTelemetrySink();
    const logSink = new InMemoryTelemetrySink();

    let now = 1000;
    const recorder = createTelemetryRecorder(config, {
      auditSinks: [auditSink],
      logSinks: [logSink],
      deps: {
        now: () => now,
        random: () => 0,
      },
    });

    recorder.enableIncidentMode({
      durationMs: 5000,
      reason: "active-incident",
    });

    await recorder.recordPolicyDecision(
      defaultPolicy(),
      "network",
      { secret: secretText("dont-leak") },
      { traceId: "trace-2", sourceIp: "198.51.100.7" },
    );

    expect(auditSink.events).toHaveLength(1);
    expect(logSink.events).toHaveLength(1);
    expect(logSink.events[0]).toMatchObject({
      eventType: "policy.decision",
      mode: "incident",
      incidentReason: "active-incident",
      redactedPayload: { secret: "[REDACTED:secret]" },
    });

    now = 7001;
    expect(recorder.getMode()).toBe("minimal");
  });

  test("env config supports azure and runtime toggles", () => {
    const config = telemetryConfigFromEnv({
      NODE_ENV: "production",
      TYPESECURE_AZURE_ENABLED: "true",
      TYPESECURE_LOGGING_ENABLED: "false",
      TYPESECURE_AUDIT_ENABLED: "true",
      TYPESECURE_LOG_SAMPLING_RATE: "0.25",
      TYPESECURE_INCIDENT_MODE: "true",
      TYPESECURE_INCIDENT_MODE_EXPIRES_AT: "12345",
    });

    expect(config.environment).toBe("production");
    expect(config.azure.enabled).toBe(true);
    expect(config.loggingEnabled).toBe(false);
    expect(config.auditEnabled).toBe(true);
    expect(config.logSamplingRate).toBeCloseTo(0.25);
    expect(config.incident.enabled).toBe(true);
    expect(config.incident.expiresAt).toBe(12345);
  });

  test("security event details are redacted before sink writes", async () => {
    const sink = new InMemoryTelemetrySink();
    const recorder = createTelemetryRecorder(
      defaultTelemetryConfig("production"),
      {
        auditSinks: [sink],
        logSinks: [sink],
      },
    );

    await recorder.recordSecurityEvent({
      name: "auth.failed",
      severity: "high",
      traceId: "trace-3",
      details: {
        token: secretText("top-secret-token"),
      },
    });

    const evt = sink.events.find((e) => e.eventType === "security.event");
    expect(evt).toBeDefined();
    expect(evt).toMatchObject({
      details: {
        token: "[REDACTED:secret]",
      },
    });
  });

  test("sink failures are isolated by default", async () => {
    const ok = new InMemoryTelemetrySink();
    const failing: TelemetrySink = {
      write: () => {
        throw new Error("sink failure");
      },
    };

    const onSinkError = jest.fn();
    const recorder = createTelemetryRecorder(
      defaultTelemetryConfig("production"),
      {
        auditSinks: [ok, failing],
        logSinks: [],
        onSinkError,
      },
    );

    await expect(
      recorder.recordPolicyDecision(
        defaultPolicy(),
        "log",
        { public: "ok" },
        { traceId: "trace-4" },
      ),
    ).resolves.toBeDefined();

    expect(ok.events).toHaveLength(1);
    expect(onSinkError).toHaveBeenCalledTimes(1);
  });

  test("sink failure mode throw propagates errors", async () => {
    const failing: TelemetrySink = {
      write: () => {
        throw new Error("sink failure");
      },
    };

    const recorder = createTelemetryRecorder(
      defaultTelemetryConfig("production"),
      {
        auditSinks: [failing],
        sinkFailureMode: "throw",
      },
    );

    await expect(
      recorder.recordPolicyDecision(
        defaultPolicy(),
        "log",
        { public: "ok" },
        { traceId: "trace-5" },
      ),
    ).rejects.toThrow("Telemetry sink write failed");
  });

  test("supports dynamic config refresh", async () => {
    let next = defaultTelemetryConfig("staging");
    const recorder = createTelemetryRecorder(
      defaultTelemetryConfig("staging"),
      {
        configProvider: {
          loadConfig: () => next,
        },
      },
    );

    expect(recorder.getMode()).toBe("minimal");

    next = {
      ...defaultTelemetryConfig("production"),
      loggingEnabled: true,
    };

    await recorder.refreshConfig();
    expect(recorder.getMode()).toBe("standard");
  });

  test("azure app insights sink supports dry run for zero-cost local verification", () => {
    const tracked: AzureAppInsightsTrackEventInput[] = [];
    const emitted: AzureAppInsightsTrackEventInput[] = [];

    const sink = createAzureApplicationInsightsSink(
      {
        trackEvent: (evt) => {
          tracked.push(evt);
        },
      },
      {
        dryRun: true,
        onEmit: (evt) => {
          emitted.push(evt);
        },
      },
    );

    sink.write({
      eventType: "security.event",
      at: Date.now(),
      environment: "production",
      mode: "incident",
      name: "auth.failed",
      severity: "high",
      traceId: "trace-6",
    });

    expect(emitted).toHaveLength(1);
    expect(tracked).toHaveLength(0);
    expect(emitted[0].name).toBe("typesecure.security.event");
  });

  test("azure readiness assessment reports missing controls", () => {
    const report = assessAzureReadiness({
      immutableArchiveEnabled: false,
      hotRetentionDays: 7,
      archiveRetentionDays: 30,
      alertsConfigured: false,
      dynamicConfigEnabled: false,
    });

    expect(report.ready).toBe(false);
    expect(report.issues.length).toBeGreaterThan(0);
  });

  test("buildIncidentForensicsSummary aggregates attacker footprint", () => {
    const summary = buildIncidentForensicsSummary(
      [
        {
          eventType: "policy.decision",
          at: 1000,
          environment: "production",
          mode: "incident",
          policy: "typesecure.default",
          action: "log",
          allowed: false,
          detectedKinds: ["pii"],
          traceId: "t1",
          sourceIp: "203.0.113.5",
          actorId: "attacker-1",
          sessionId: "s1",
        },
        {
          eventType: "security.event",
          at: 1500,
          environment: "production",
          mode: "incident",
          name: "auth.failed",
          severity: "high",
          traceId: "t2",
          sourceIp: "203.0.113.5",
          actorId: "attacker-1",
          sessionId: "s1",
        },
      ],
      { generatedAt: 5000 },
    );

    expect(summary.totalEvents).toBe(2);
    expect(summary.deniedPolicyDecisions).toBe(1);
    expect(summary.topSourceIps[0]).toEqual({
      sourceIp: "203.0.113.5",
      count: 2,
    });
    expect(summary.topActors[0]).toEqual({ actorId: "attacker-1", count: 2 });
    expect(summary.subjects[0]).toMatchObject({
      actorId: "attacker-1",
      sourceIp: "203.0.113.5",
      eventCount: 2,
      deniedPolicyDecisions: 1,
      securityEventCount: 1,
    });
  });

  test("detectTelemetryAlerts flags denied/auth spikes and critical events", () => {
    const events: TelemetryEvent[] = [
      ...Array.from({ length: 3 }, (_, i) => ({
        eventType: "policy.decision" as const,
        at: 1000 + i,
        environment: "production" as const,
        mode: "incident" as const,
        policy: "typesecure.default",
        action: "log" as const,
        allowed: false,
        detectedKinds: ["pii"] as DataClassification[],
        traceId: `p-${i}`,
        sourceIp: "198.51.100.10",
      })),
      ...Array.from({ length: 3 }, (_, i) => ({
        eventType: "security.event" as const,
        at: 1100 + i,
        environment: "production" as const,
        mode: "incident" as const,
        name: "auth.failed",
        severity: "high" as const,
        traceId: `a-${i}`,
        sourceIp: "198.51.100.10",
        actorId: "acct-1",
      })),
      {
        eventType: "security.event" as const,
        at: 1200,
        environment: "production" as const,
        mode: "incident" as const,
        name: "privilege.escalation",
        severity: "critical" as const,
        traceId: "c-1",
      },
    ];

    const alerts = detectTelemetryAlerts(events, {
      windowMs: 60_000,
      deniedPolicyDecisionsPerIpThreshold: 3,
      authFailedPerIpThreshold: 3,
      authFailedPerActorThreshold: 3,
      criticalSecurityEventThreshold: 1,
    });

    expect(alerts.some((a) => a.name === "policy.denied_spike_by_ip")).toBe(
      true,
    );
    expect(alerts.some((a) => a.name === "auth.failed_spike_by_ip")).toBe(true);
    expect(alerts.some((a) => a.name === "auth.failed_spike_by_actor")).toBe(
      true,
    );
    expect(alerts.some((a) => a.name === "security.critical_event")).toBe(true);
  });
});
