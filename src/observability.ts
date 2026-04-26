import { type DataClassification } from "./classification";
import {
  decide,
  type Policy,
  type PolicyAction,
  type PolicyDecision,
} from "./policy";
import { redact, type RedactOptions } from "./redaction";

export type EnvironmentTier =
  | "production"
  | "staging"
  | "test"
  | "development"
  | "unknown";

export type TelemetryMode = "off" | "minimal" | "standard" | "incident";

export type AzureTelemetryConfig = Readonly<{
  enabled: boolean;
  disableDetailedLogsInNonProduction: boolean;
  immutableArchiveEnabled: boolean;
}>;

export type IncidentMode = Readonly<{
  enabled: boolean;
  expiresAt?: number;
  reason?: string;
  enabledBy?: string;
}>;

export type TelemetryConfig = Readonly<{
  environment: EnvironmentTier;
  loggingEnabled: boolean;
  auditEnabled: boolean;
  minimalAuditEnabled: boolean;
  logSamplingRate: number;
  incident: IncidentMode;
  azure: AzureTelemetryConfig;
}>;

export type IncidentModeInput = Readonly<{
  durationMs?: number;
  reason?: string;
  enabledBy?: string;
  expiresAt?: number;
}>;

export type EventContext = Readonly<{
  traceId: string;
  correlationId?: string;
  sessionId?: string;
  actorId?: string;
  sourceIp?: string;
  userAgent?: string;
  method?: string;
  route?: string;
  instanceId?: string;
}>;

export type PolicyTelemetryEvent = Readonly<{
  eventType: "policy.decision";
  at: number;
  environment: EnvironmentTier;
  mode: TelemetryMode;
  policy: string;
  action: PolicyAction;
  allowed: boolean;
  reason?: string;
  detectedKinds: DataClassification[];
  traceId: string;
  correlationId?: string;
  sessionId?: string;
  actorId?: string;
  sourceIp?: string;
  userAgent?: string;
  method?: string;
  route?: string;
  instanceId?: string;
  incidentReason?: string;
  redactedPayload?: unknown;
}>;

export type SecurityEvent = Readonly<{
  eventType: "security.event";
  at: number;
  environment: EnvironmentTier;
  mode: TelemetryMode;
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  traceId: string;
  correlationId?: string;
  sessionId?: string;
  actorId?: string;
  sourceIp?: string;
  userAgent?: string;
  method?: string;
  route?: string;
  instanceId?: string;
  details?: unknown;
}>;

export type TelemetryEvent = PolicyTelemetryEvent | SecurityEvent;

export interface TelemetrySink {
  write(event: TelemetryEvent): void | Promise<void>;
}

export class InMemoryTelemetrySink implements TelemetrySink {
  public readonly events: TelemetryEvent[] = [];

  write(event: TelemetryEvent): void {
    this.events.push(event);
  }
}

export class ConsoleTelemetrySink implements TelemetrySink {
  private readonly logger: Pick<Console, "info" | "warn" | "error">;

  constructor(logger: Pick<Console, "info" | "warn" | "error"> = console) {
    this.logger = logger;
  }

  write(event: TelemetryEvent): void {
    const json = JSON.stringify(event);
    if (event.eventType === "security.event") {
      if (event.severity === "critical" || event.severity === "high") {
        this.logger.error(json);
        return;
      }
      if (event.severity === "medium") {
        this.logger.warn(json);
        return;
      }
    }
    this.logger.info(json);
  }
}

export type AzureAppInsightsTrackEventInput = Readonly<{
  name: string;
  properties?: Record<string, string>;
  measurements?: Record<string, number>;
}>;

export type AzureApplicationInsightsClient = Readonly<{
  trackEvent(event: AzureAppInsightsTrackEventInput): void;
  flush?: (options?: { callback?: () => void }) => void;
}>;

export type AzureAppInsightsSinkOptions = Readonly<{
  eventNamePrefix?: string;
  dryRun?: boolean;
  onEmit?: (
    event: AzureAppInsightsTrackEventInput,
    sourceEvent: TelemetryEvent,
  ) => void;
}>;

export function createAzureApplicationInsightsSink(
  client: AzureApplicationInsightsClient,
  options?: AzureAppInsightsSinkOptions,
): TelemetrySink {
  const prefix = options?.eventNamePrefix ?? "typesecure";
  const dryRun = options?.dryRun ?? false;

  return {
    write(event: TelemetryEvent): void {
      const envelope: AzureAppInsightsTrackEventInput = {
        name: `${prefix}.${event.eventType}`,
        properties: {
          eventType: event.eventType,
          environment: event.environment,
          mode: event.mode,
          traceId: event.traceId,
          payload: JSON.stringify(event),
        },
        measurements: {
          at: event.at,
        },
      };

      options?.onEmit?.(envelope, event);
      if (!dryRun) {
        client.trackEvent(envelope);
      }
    },
  };
}

type TelemetryDeps = Readonly<{
  now?: () => number;
  random?: () => number;
}>;

export type SinkFailureMode = "ignore" | "throw";

export type TelemetrySinkErrorContext = Readonly<{
  phase: "audit" | "log";
  sinkIndex: number;
  sinkName: string;
  event: TelemetryEvent;
  error: unknown;
}>;

export type TelemetryConfigProvider = Readonly<{
  loadConfig: () => TelemetryConfig | Promise<TelemetryConfig>;
}>;

export type AzureReadinessAssessmentInput = Readonly<{
  appInsightsConnectionString?: string;
  logAnalyticsWorkspaceId?: string;
  dataCollectionEndpoint?: string;
  dataCollectionRuleId?: string;
  immutableArchiveEnabled: boolean;
  hotRetentionDays?: number;
  archiveRetentionDays?: number;
  alertsConfigured?: boolean;
  dynamicConfigEnabled?: boolean;
}>;

export type AzureReadinessAssessment = Readonly<{
  ready: boolean;
  issues: string[];
}>;

export function assessAzureReadiness(
  input: AzureReadinessAssessmentInput,
): AzureReadinessAssessment {
  const issues: string[] = [];

  if (!input.appInsightsConnectionString) {
    issues.push("Missing Application Insights connection string.");
  }
  if (!input.logAnalyticsWorkspaceId) {
    issues.push("Missing Log Analytics workspace id.");
  }

  const hasDcrIngestion =
    Boolean(input.dataCollectionEndpoint) &&
    Boolean(input.dataCollectionRuleId);
  if (!hasDcrIngestion) {
    issues.push(
      "Missing DCR ingestion settings (dataCollectionEndpoint + dataCollectionRuleId).",
    );
  }

  if (!input.immutableArchiveEnabled) {
    issues.push("Immutable archive is disabled.");
  }

  if ((input.hotRetentionDays ?? 0) < 30) {
    issues.push("Hot retention should be at least 30 days.");
  }
  if ((input.archiveRetentionDays ?? 0) < 180) {
    issues.push("Archive retention should be at least 180 days.");
  }

  if (!input.alertsConfigured) {
    issues.push("Alert rules are not configured.");
  }
  if (!input.dynamicConfigEnabled) {
    issues.push("Dynamic runtime config refresh is not configured.");
  }

  return {
    ready: issues.length === 0,
    issues,
  };
}

function normalizeEnvironment(value?: string): EnvironmentTier {
  switch ((value ?? "").toLowerCase()) {
    case "prod":
    case "production":
      return "production";
    case "stage":
    case "staging":
      return "staging";
    case "test":
      return "test";
    case "dev":
    case "development":
      return "development";
    default:
      return "unknown";
  }
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  switch (value.toLowerCase()) {
    case "1":
    case "true":
    case "yes":
    case "on":
      return true;
    case "0":
    case "false":
    case "no":
    case "off":
      return false;
    default:
      return fallback;
  }
}

function parseNumber(
  value: string | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  if (parsed < min) return min;
  if (parsed > max) return max;
  return parsed;
}

function resolveMode(config: TelemetryConfig, now: number): TelemetryMode {
  const incidentActive =
    config.incident.enabled &&
    (config.incident.expiresAt === undefined ||
      now <= config.incident.expiresAt);

  if (incidentActive) return "incident";

  if (!config.loggingEnabled) {
    return config.minimalAuditEnabled ? "minimal" : "off";
  }

  if (
    config.azure.enabled &&
    config.azure.disableDetailedLogsInNonProduction &&
    config.environment !== "production"
  ) {
    return config.minimalAuditEnabled ? "minimal" : "off";
  }

  return "standard";
}

function shouldSample(config: TelemetryConfig, random: () => number): boolean {
  if (config.logSamplingRate >= 1) return true;
  if (config.logSamplingRate <= 0) return false;
  return random() <= config.logSamplingRate;
}

function buildEventContext(
  context: EventContext,
): Pick<
  PolicyTelemetryEvent,
  | "traceId"
  | "correlationId"
  | "sessionId"
  | "actorId"
  | "sourceIp"
  | "userAgent"
  | "method"
  | "route"
  | "instanceId"
> {
  return {
    traceId: context.traceId,
    correlationId: context.correlationId,
    sessionId: context.sessionId,
    actorId: context.actorId,
    sourceIp: context.sourceIp,
    userAgent: context.userAgent,
    method: context.method,
    route: context.route,
    instanceId: context.instanceId,
  };
}

export function defaultTelemetryConfig(
  environment: EnvironmentTier,
): TelemetryConfig {
  const isProduction = environment === "production";
  const isStagingLike = environment === "staging" || environment === "test";

  return {
    environment,
    loggingEnabled: isProduction,
    auditEnabled: true,
    minimalAuditEnabled: true,
    logSamplingRate: isStagingLike ? 0.1 : 1,
    incident: {
      enabled: false,
    },
    azure: {
      enabled: false,
      disableDetailedLogsInNonProduction: true,
      immutableArchiveEnabled: true,
    },
  };
}

export function telemetryConfigFromEnv(
  env: Record<string, string | undefined>,
): TelemetryConfig {
  const environment = normalizeEnvironment(
    env.TYPESECURE_ENV ?? env.APP_ENV ?? env.NODE_ENV,
  );
  const defaults = defaultTelemetryConfig(environment);

  const incidentEnabled = parseBoolean(
    env.TYPESECURE_INCIDENT_MODE ?? env.INCIDENT_MODE,
    defaults.incident.enabled,
  );
  const incidentExpiresAt = parseNumber(
    env.TYPESECURE_INCIDENT_MODE_EXPIRES_AT ?? env.INCIDENT_MODE_EXPIRES_AT,
    NaN,
    0,
    Number.MAX_SAFE_INTEGER,
  );

  return {
    ...defaults,
    loggingEnabled: parseBoolean(
      env.TYPESECURE_LOGGING_ENABLED ?? env.LOGGING_ENABLED,
      defaults.loggingEnabled,
    ),
    auditEnabled: parseBoolean(
      env.TYPESECURE_AUDIT_ENABLED ?? env.AUDIT_ENABLED,
      defaults.auditEnabled,
    ),
    minimalAuditEnabled: parseBoolean(
      env.TYPESECURE_MIN_AUDIT_ENABLED ?? env.MIN_AUDIT_ENABLED,
      defaults.minimalAuditEnabled,
    ),
    logSamplingRate: parseNumber(
      env.TYPESECURE_LOG_SAMPLING_RATE ?? env.LOG_SAMPLING_RATE,
      defaults.logSamplingRate,
      0,
      1,
    ),
    incident: {
      enabled: incidentEnabled,
      expiresAt: Number.isFinite(incidentExpiresAt)
        ? incidentExpiresAt
        : undefined,
      reason: env.TYPESECURE_INCIDENT_REASON ?? env.INCIDENT_REASON,
      enabledBy: env.TYPESECURE_INCIDENT_ENABLED_BY ?? env.INCIDENT_ENABLED_BY,
    },
    azure: {
      enabled: parseBoolean(
        env.TYPESECURE_AZURE_ENABLED ?? env.AZURE_ENABLED,
        defaults.azure.enabled,
      ),
      disableDetailedLogsInNonProduction: parseBoolean(
        env.TYPESECURE_AZURE_DISABLE_NONPROD_LOGS ??
          env.AZURE_DISABLE_NONPROD_LOGS,
        defaults.azure.disableDetailedLogsInNonProduction,
      ),
      immutableArchiveEnabled: parseBoolean(
        env.TYPESECURE_IMMUTABLE_ARCHIVE_ENABLED ??
          env.IMMUTABLE_ARCHIVE_ENABLED,
        defaults.azure.immutableArchiveEnabled,
      ),
    },
  };
}

export type TelemetryRecorder = ReturnType<typeof createTelemetryRecorder>;

export function createTelemetryRecorder(
  config: TelemetryConfig,
  options?: Readonly<{
    auditSinks?: readonly TelemetrySink[];
    logSinks?: readonly TelemetrySink[];
    redaction?: RedactOptions;
    deps?: TelemetryDeps;
    sinkFailureMode?: SinkFailureMode;
    onSinkError?: (context: TelemetrySinkErrorContext) => void | Promise<void>;
    configProvider?: TelemetryConfigProvider;
  }>,
): {
  getConfig: () => TelemetryConfig;
  setConfig: (next: TelemetryConfig) => void;
  getMode: () => TelemetryMode;
  refreshConfig: () => Promise<TelemetryConfig>;
  startAutoRefresh: (intervalMs: number) => () => void;
  stopAutoRefresh: () => void;
  enableIncidentMode: (input?: IncidentModeInput) => void;
  disableIncidentMode: () => void;
  recordPolicyDecision: (
    policy: Policy,
    action: PolicyAction,
    data: unknown,
    context: EventContext,
  ) => Promise<PolicyDecision>;
  recordSecurityEvent: (
    event: Omit<SecurityEvent, "at" | "environment" | "mode" | "eventType">,
  ) => Promise<void>;
} {
  let current = config;
  let refreshTimer: ReturnType<typeof globalThis.setInterval> | undefined;

  const now = options?.deps?.now ?? Date.now;
  const random = options?.deps?.random ?? Math.random;
  const auditSinks = options?.auditSinks ?? [];
  const logSinks = options?.logSinks ?? [];
  const redaction = options?.redaction;
  const sinkFailureMode = options?.sinkFailureMode ?? "ignore";

  const handleSinkError = async (
    context: TelemetrySinkErrorContext,
  ): Promise<void> => {
    if (!options?.onSinkError) return;
    try {
      await options.onSinkError(context);
    } catch {
      // Never let error reporting fail hard.
    }
  };

  const writeAllSafe = async (
    sinks: readonly TelemetrySink[],
    event: TelemetryEvent,
    phase: "audit" | "log",
  ): Promise<void> => {
    if (sinks.length === 0) return;

    const results = await Promise.allSettled(
      sinks.map((sink) => Promise.resolve().then(() => sink.write(event))),
    );

    const failures: unknown[] = [];
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.status === "rejected") {
        failures.push(result.reason);
        const sink = sinks[i];
        await handleSinkError({
          phase,
          sinkIndex: i,
          sinkName: sink.constructor?.name ?? "anonymous-sink",
          event,
          error: result.reason,
        });
      }
    }

    if (sinkFailureMode === "throw" && failures.length > 0) {
      throw new AggregateError(failures, "Telemetry sink write failed");
    }
  };

  const effectiveMode = (): TelemetryMode => {
    const ts = now();
    if (
      current.incident.enabled &&
      current.incident.expiresAt !== undefined &&
      ts > current.incident.expiresAt
    ) {
      current = {
        ...current,
        incident: {
          enabled: false,
        },
      };
    }

    return resolveMode(current, ts);
  };

  const refreshConfig = async (): Promise<TelemetryConfig> => {
    if (!options?.configProvider) return current;
    const next = await options.configProvider.loadConfig();
    current = next;
    return current;
  };

  const stopAutoRefresh = (): void => {
    if (refreshTimer !== undefined) {
      globalThis.clearInterval(refreshTimer);
      refreshTimer = undefined;
    }
  };

  const startAutoRefresh = (intervalMs: number): (() => void) => {
    stopAutoRefresh();
    refreshTimer = globalThis.setInterval(() => {
      void refreshConfig();
    }, intervalMs);

    return stopAutoRefresh;
  };

  return {
    getConfig: (): TelemetryConfig => current,
    setConfig: (next: TelemetryConfig): void => {
      current = next;
    },
    getMode: (): TelemetryMode => effectiveMode(),
    refreshConfig,
    startAutoRefresh,
    stopAutoRefresh,
    enableIncidentMode: (input?: IncidentModeInput): void => {
      const ts = now();
      const expiresAt =
        input?.expiresAt ??
        (input?.durationMs !== undefined ? ts + input.durationMs : undefined);
      current = {
        ...current,
        incident: {
          enabled: true,
          expiresAt,
          reason: input?.reason,
          enabledBy: input?.enabledBy,
        },
      };
    },
    disableIncidentMode: (): void => {
      current = {
        ...current,
        incident: {
          enabled: false,
        },
      };
    },
    recordPolicyDecision: async (
      policy: Policy,
      action: PolicyAction,
      data: unknown,
      context: EventContext,
    ): Promise<PolicyDecision> => {
      const decision = decide(policy, action, data);
      const ts = now();
      const mode = effectiveMode();
      const contextFields = buildEventContext(context);

      const event: PolicyTelemetryEvent = {
        eventType: "policy.decision",
        at: ts,
        environment: current.environment,
        mode,
        policy: policy.name,
        action,
        allowed: decision.allowed,
        reason: decision.reason,
        detectedKinds: decision.detectedKinds ?? [],
        incidentReason: current.incident.reason,
        ...contextFields,
      };

      const shouldWriteAudit =
        current.minimalAuditEnabled || current.auditEnabled;
      if (shouldWriteAudit) {
        await writeAllSafe(auditSinks, event, "audit");
      }

      const canWriteDetailed =
        (mode === "standard" || mode === "incident") &&
        shouldSample(current, random);
      if (canWriteDetailed) {
        const detailed: PolicyTelemetryEvent = {
          ...event,
          redactedPayload: redact(data, redaction),
        };
        await writeAllSafe(logSinks, detailed, "log");
      }

      return decision;
    },
    recordSecurityEvent: async (
      event: Omit<SecurityEvent, "at" | "environment" | "mode" | "eventType">,
    ): Promise<void> => {
      const ts = now();
      const mode = effectiveMode();
      const out: SecurityEvent = {
        ...event,
        details:
          event.details === undefined
            ? undefined
            : redact(event.details, redaction),
        eventType: "security.event",
        at: ts,
        environment: current.environment,
        mode,
      };

      const shouldWriteAudit =
        current.minimalAuditEnabled || current.auditEnabled;
      if (shouldWriteAudit) {
        await writeAllSafe(auditSinks, out, "audit");
      }

      const canWriteDetailed =
        (mode === "standard" || mode === "incident") &&
        shouldSample(current, random);
      if (canWriteDetailed) {
        await writeAllSafe(logSinks, out, "log");
      }
    },
  };
}

export type IncidentSubjectSummary = Readonly<{
  actorId?: string;
  sourceIp?: string;
  sessionId?: string;
  firstSeenAt: number;
  lastSeenAt: number;
  eventCount: number;
  deniedPolicyDecisions: number;
  securityEventCount: number;
}>;

export type IncidentForensicsSummary = Readonly<{
  generatedAt: number;
  totalEvents: number;
  deniedPolicyDecisions: number;
  subjects: IncidentSubjectSummary[];
  topSourceIps: Array<Readonly<{ sourceIp: string; count: number }>>;
  topActors: Array<Readonly<{ actorId: string; count: number }>>;
}>;

export type AlertSeverity = "low" | "medium" | "high" | "critical";

export type TelemetryAlert = Readonly<{
  name:
    | "policy.denied_spike_by_ip"
    | "auth.failed_spike_by_ip"
    | "auth.failed_spike_by_actor"
    | "security.critical_event";
  severity: AlertSeverity;
  count: number;
  sourceIp?: string;
  actorId?: string;
  windowStartAt: number;
  windowEndAt: number;
  reason: string;
}>;

export type AlertRules = Readonly<{
  windowMs?: number;
  deniedPolicyDecisionsPerIpThreshold?: number;
  authFailedPerIpThreshold?: number;
  authFailedPerActorThreshold?: number;
  criticalSecurityEventThreshold?: number;
}>;

type SubjectAccumulator = {
  actorId?: string;
  sourceIp?: string;
  sessionId?: string;
  firstSeenAt: number;
  lastSeenAt: number;
  eventCount: number;
  deniedPolicyDecisions: number;
  securityEventCount: number;
};

function sourceIpOf(event: TelemetryEvent): string | undefined {
  return event.sourceIp;
}

function actorIdOf(event: TelemetryEvent): string | undefined {
  return event.actorId;
}

function sessionIdOf(event: TelemetryEvent): string | undefined {
  return event.sessionId;
}

function subjectKey(event: TelemetryEvent): string {
  const actor = actorIdOf(event) ?? "";
  const ip = sourceIpOf(event) ?? "";
  const session = sessionIdOf(event) ?? "";
  return `actor:${actor}|ip:${ip}|session:${session}`;
}

function isAuthFailedEvent(event: TelemetryEvent): boolean {
  if (event.eventType !== "security.event") return false;
  return /(auth|login)\.failed|credential\.stuffing/i.test(event.name);
}

export function buildIncidentForensicsSummary(
  events: readonly TelemetryEvent[],
  options?: Readonly<{
    generatedAt?: number;
    maxSubjects?: number;
  }>,
): IncidentForensicsSummary {
  const generatedAt = options?.generatedAt ?? Date.now();
  const maxSubjects = options?.maxSubjects ?? 100;

  const subjects = new Map<string, SubjectAccumulator>();
  const ipCounts = new Map<string, number>();
  const actorCounts = new Map<string, number>();
  let deniedPolicyDecisions = 0;

  for (const event of events) {
    const key = subjectKey(event);
    const existing = subjects.get(key);
    const eventAt = event.at;
    const sourceIp = sourceIpOf(event);
    const actorId = actorIdOf(event);

    if (sourceIp) {
      ipCounts.set(sourceIp, (ipCounts.get(sourceIp) ?? 0) + 1);
    }
    if (actorId) {
      actorCounts.set(actorId, (actorCounts.get(actorId) ?? 0) + 1);
    }

    if (!existing) {
      subjects.set(key, {
        actorId,
        sourceIp,
        sessionId: sessionIdOf(event),
        firstSeenAt: eventAt,
        lastSeenAt: eventAt,
        eventCount: 1,
        deniedPolicyDecisions:
          event.eventType === "policy.decision" && !event.allowed ? 1 : 0,
        securityEventCount: event.eventType === "security.event" ? 1 : 0,
      });
    } else {
      existing.firstSeenAt = Math.min(existing.firstSeenAt, eventAt);
      existing.lastSeenAt = Math.max(existing.lastSeenAt, eventAt);
      existing.eventCount += 1;
      if (event.eventType === "policy.decision" && !event.allowed) {
        existing.deniedPolicyDecisions += 1;
      }
      if (event.eventType === "security.event") {
        existing.securityEventCount += 1;
      }
    }

    if (event.eventType === "policy.decision" && !event.allowed) {
      deniedPolicyDecisions += 1;
    }
  }

  const sortedSubjects = [...subjects.values()]
    .sort((a, b) => b.eventCount - a.eventCount)
    .slice(0, maxSubjects)
    .map((s) => ({ ...s }));

  const topSourceIps = [...ipCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([sourceIp, count]) => ({ sourceIp, count }));

  const topActors = [...actorCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([actorId, count]) => ({ actorId, count }));

  return {
    generatedAt,
    totalEvents: events.length,
    deniedPolicyDecisions,
    subjects: sortedSubjects,
    topSourceIps,
    topActors,
  };
}

export function detectTelemetryAlerts(
  events: readonly TelemetryEvent[],
  rules?: AlertRules,
): TelemetryAlert[] {
  if (events.length === 0) return [];

  const defaults = {
    windowMs: 15 * 60 * 1000,
    deniedPolicyDecisionsPerIpThreshold: 20,
    authFailedPerIpThreshold: 10,
    authFailedPerActorThreshold: 8,
    criticalSecurityEventThreshold: 1,
  } as const;

  const settings = { ...defaults, ...rules };

  let maxAt = events[0].at;
  for (const event of events) {
    if (event.at > maxAt) maxAt = event.at;
  }

  const windowEndAt = maxAt;
  const windowStartAt = windowEndAt - settings.windowMs;
  const inWindow = events.filter(
    (e) => e.at >= windowStartAt && e.at <= windowEndAt,
  );

  const deniedByIp = new Map<string, number>();
  const authByIp = new Map<string, number>();
  const authByActor = new Map<string, number>();
  let criticalCount = 0;

  for (const event of inWindow) {
    if (
      event.eventType === "policy.decision" &&
      !event.allowed &&
      event.sourceIp
    ) {
      deniedByIp.set(event.sourceIp, (deniedByIp.get(event.sourceIp) ?? 0) + 1);
    }

    if (isAuthFailedEvent(event)) {
      if (event.sourceIp) {
        authByIp.set(event.sourceIp, (authByIp.get(event.sourceIp) ?? 0) + 1);
      }
      if (event.actorId) {
        authByActor.set(
          event.actorId,
          (authByActor.get(event.actorId) ?? 0) + 1,
        );
      }
    }

    if (event.eventType === "security.event" && event.severity === "critical") {
      criticalCount += 1;
    }
  }

  const alerts: TelemetryAlert[] = [];

  for (const [sourceIp, count] of deniedByIp.entries()) {
    if (count >= settings.deniedPolicyDecisionsPerIpThreshold) {
      alerts.push({
        name: "policy.denied_spike_by_ip",
        severity: "high",
        count,
        sourceIp,
        windowStartAt,
        windowEndAt,
        reason: `Denied policy decisions from ${sourceIp} reached ${count}.`,
      });
    }
  }

  for (const [sourceIp, count] of authByIp.entries()) {
    if (count >= settings.authFailedPerIpThreshold) {
      alerts.push({
        name: "auth.failed_spike_by_ip",
        severity: "high",
        count,
        sourceIp,
        windowStartAt,
        windowEndAt,
        reason: `Auth failures from ${sourceIp} reached ${count}.`,
      });
    }
  }

  for (const [actorId, count] of authByActor.entries()) {
    if (count >= settings.authFailedPerActorThreshold) {
      alerts.push({
        name: "auth.failed_spike_by_actor",
        severity: "medium",
        count,
        actorId,
        windowStartAt,
        windowEndAt,
        reason: `Auth failures for actor ${actorId} reached ${count}.`,
      });
    }
  }

  if (criticalCount >= settings.criticalSecurityEventThreshold) {
    alerts.push({
      name: "security.critical_event",
      severity: "critical",
      count: criticalCount,
      windowStartAt,
      windowEndAt,
      reason: `Critical security events reached ${criticalCount}.`,
    });
  }

  return alerts.sort((a, b) => b.count - a.count);
}
