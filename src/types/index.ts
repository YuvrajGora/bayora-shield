/**
 * Bayora Shield - Core TypeScript Type Definitions
 */

export type Role = 'admin' | 'red_team' | 'blue_team';

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  token?: string;
  avatarSeed: string;
}

export type RuleMatchType = 'keyword' | 'regex' | 'contains_phrase';
export type RuleAction = 'BLOCK' | 'FLAG';
export type RuleSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface DefensiveRule {
  id: string;
  name: string;
  description: string;
  matchType: RuleMatchType;
  pattern: string;
  action: RuleAction;
  severity: RuleSeverity;
  enabled: boolean;
  category: string;
  createdAt: string;
  updatedAt: string;
  hitCount: number;
  createdBy: string;
}

export type RunStatus = 'queued' | 'running' | 'completed' | 'failed';
export type GatewayDecision = 'BLOCKED' | 'ALLOWED' | 'FLAGGED_AND_PASSED' | 'PENDING';

export interface TestRun {
  id: string;
  title: string;
  prompt: string;
  sealed: boolean;
  status: RunStatus;
  decision: GatewayDecision;
  triggeredRules: Array<{
    id: string;
    name: string;
    category: string;
    severity: RuleSeverity;
    action: RuleAction;
  }>;
  mockAiResponse: {
    text: string;
    tokens: number;
    latencyMs: number;
    model: string;
    deterministicHash: string;
  } | null;
  createdBy: string;
  createdByEmail: string;
  createdRole: Role;
  createdAt: string;
  completedAt?: string;
  notes?: string;
}

export type AuditEventType =
  | 'TEST_SUBMISSION'
  | 'GATEWAY_BLOCKED'
  | 'GATEWAY_ALLOWED'
  | 'ACCESS_DENIAL'
  | 'RULE_CREATED'
  | 'RULE_UPDATED'
  | 'RULE_DELETED'
  | 'SESSION_LOGIN'
  | 'SEALED_PAYLOAD_PROTECTED'
  | 'SECURITY_TEST_SUITE_RUN';

export type AuditSeverity = 'INFO' | 'WARNING' | 'CRITICAL';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  severity: AuditSeverity;
  actorEmail: string;
  actorRole: Role | 'anonymous';
  targetResource: string;
  decision: 'PERMITTED' | 'BLOCKED' | 'DENIED' | 'RECORDED';
  details: string;
  ipAddress?: string;
  previousHash?: string;
  hash?: string;
  metadata?: Record<string, any>;
}

export interface AuditIntegrityReport {
  valid: boolean;
  totalEntries: number;
  verifiedEntries: number;
  brokenAtIndex?: number;
  brokenEntryId?: string;
  expectedHash?: string;
  actualHash?: string;
  reason?: string;
  verifiedAt: string;
}

export interface AutomatedTestResult {
  id: string;
  name: string;
  description: string;
  category: 'ACCESS_CONTROL' | 'PAYLOAD_SEALING' | 'GATEWAY_DECISION' | 'DYNAMIC_POLICY';
  status: 'passed' | 'failed' | 'running';
  expected: string;
  actual: string;
  httpStatusExpected: number;
  httpStatusActual: number;
  durationMs: number;
  passed: boolean;
  timestamp: string;
  evidence: string;
}

export interface StorageInfo {
  type: string;
  description: string;
  location: string;
  persistenceGuarantees: string[];
  limitations: string[];
  recordsCount: {
    rules: number;
    testRuns: number;
    auditLogs: number;
  };
}
