import {
  User,
  DefensiveRule,
  TestRun,
  AuditLogEntry,
  AutomatedTestResult,
  StorageInfo,
  Role,
} from '../types/index.ts';

const TOKEN_KEY = 'bayora_shield_token';
const USER_KEY = 'bayora_shield_user';

export const authStorage = {
  getToken(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  },
  setToken(token: string) {
    localStorage.setItem(TOKEN_KEY, token);
  },
  getUser(): User | null {
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  },
  setUser(user: User) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
};

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = authStorage.getToken();
  const headers = new Headers(options.headers || {});

  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(endpoint, {
    ...options,
    headers,
  });

  const contentType = response.headers.get('content-type');
  const isJson = contentType && contentType.includes('application/json');
  const data = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const error: any = new Error(
      (data && data.error) || (data && data.message) || `HTTP ${response.status}: ${response.statusText}`
    );
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data as T;
}

export const api = {
  // Auth
  async login(credentials: { role?: Role; email?: string; password: string }): Promise<{ user: User; token: string; expiresAt: string }> {
    const res = await request<{ user: User; token: string; expiresAt: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    authStorage.setToken(res.token);
    authStorage.setUser(res.user);
    return res;
  },

  async logout(): Promise<void> {
    try {
      await request('/api/auth/logout', { method: 'POST' });
    } catch {
      // Ignore network errors on logout
    } finally {
      authStorage.clear();
    }
  },

  async getDemoAccounts(): Promise<{ accounts: Array<{ role: Role; name: string; email: string; avatarSeed: string }> }> {
    return request('/api/auth/demo-accounts');
  },

  async getCurrentUser(): Promise<{ user: User }> {
    return request<{ user: User }>('/api/auth/me');
  },

  // Rules (Blue Team & Admin)
  async getRules(): Promise<{ rules: DefensiveRule[] }> {
    return request<{ rules: DefensiveRule[] }>('/api/rules');
  },

  async createRule(rule: Partial<DefensiveRule>): Promise<{ rule: DefensiveRule }> {
    return request<{ rule: DefensiveRule }>('/api/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    });
  },

  async updateRule(id: string, updates: Partial<DefensiveRule>): Promise<{ rule: DefensiveRule }> {
    return request<{ rule: DefensiveRule }>(`/api/rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  },

  async deleteRule(id: string): Promise<{ message: string; deletedRule: DefensiveRule }> {
    return request<{ message: string; deletedRule: DefensiveRule }>(`/api/rules/${id}`, {
      method: 'DELETE',
    });
  },

  // Test Runs
  async getRuns(): Promise<{ runs: TestRun[] }> {
    return request<{ runs: TestRun[] }>('/api/runs');
  },

  async getRunById(id: string): Promise<{ run: TestRun }> {
    return request<{ run: TestRun }>(`/api/runs/${id}`);
  },

  async getRunRawPayload(id: string): Promise<{ runId: string; status: string; payload: string; released: boolean }> {
    return request<{ runId: string; status: string; payload: string; released: boolean }>(`/api/runs/${id}/payload`);
  },

  async createRun(title: string, prompt: string, simulateDelayedCompletion = false): Promise<{ run: TestRun; message?: string }> {
    return request<{ run: TestRun; message?: string }>('/api/runs', {
      method: 'POST',
      body: JSON.stringify({ title, prompt, simulateDelayedCompletion }),
    });
  },

  // Policy Gateway
  async evaluateGatewayPrompt(prompt: string): Promise<{
    decision: 'BLOCKED' | 'ALLOWED' | 'FLAGGED_AND_PASSED';
    triggeredRules: Array<{
      id: string;
      name: string;
      category: string;
      severity: string;
      action: string;
    }>;
    mockAiResponse: any;
    auditLogId: string;
    evaluatedAt: string;
  }> {
    return request('/api/gateway/evaluate', {
      method: 'POST',
      body: JSON.stringify({ prompt }),
    });
  },

  // Audit Logs
  async getAuditLogs(params?: { eventType?: string; severity?: string; search?: string }): Promise<{ logs: AuditLogEntry[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.eventType && params.eventType !== 'ALL') query.set('eventType', params.eventType);
    if (params?.severity && params.severity !== 'ALL') query.set('severity', params.severity);
    if (params?.search) query.set('search', params.search);

    const queryString = query.toString();
    const url = `/api/audit${queryString ? `?${queryString}` : ''}`;
    return request<{ logs: AuditLogEntry[]; total: number }>(url);
  },

  // Automated Test Suite
  async runAutomatedTests(): Promise<{
    summary: {
      total: number;
      passed: number;
      failed: number;
      durationMs: number;
      allPassed: boolean;
      executedAt: string;
    };
    results: AutomatedTestResult[];
  }> {
    return request('/api/tests/run', {
      method: 'POST',
    });
  },

  // System
  async resetDatabase(): Promise<{ message: string }> {
    return request('/api/system/reset', {
      method: 'POST',
    });
  },

  async getStorageInfo(): Promise<StorageInfo> {
    return request<StorageInfo>('/api/storage/info');
  },
};
