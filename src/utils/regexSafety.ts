/**
 * Bayora Shield — Safe Regex Evaluation Engine (SEC-04)
 *
 * Provides static pattern safety analysis and ReDoS mitigation.
 * Rejects catastrophic backtracking patterns, nested quantifiers,
 * and dangerous quantifier repetition bounds.
 */

export interface RegexSafetyResult {
  safe: boolean;
  reason?: string;
}

/**
 * Validates a regular expression pattern against known ReDoS anti-patterns.
 * Prevents catastrophic backtracking patterns from entering the policy engine.
 */
export function validateRegexSafety(pattern: string): RegexSafetyResult {
  if (!pattern || typeof pattern !== 'string') {
    return { safe: false, reason: 'Pattern must be a non-empty string.' };
  }

  // Reject excessively long patterns that could degrade parsing performance
  if (pattern.length > 500) {
    return {
      safe: false,
      reason: 'Pattern exceeds maximum allowable length of 500 characters.',
    };
  }

  // 1. Verify standard regex syntax
  try {
    new RegExp(pattern);
  } catch (err: any) {
    return {
      safe: false,
      reason: `Invalid regular expression syntax: ${err.message}`,
    };
  }

  // 2. Reject nested quantifiers: (a+)+, (a*)*, (a+)*, ([a-z]+)+, (foo|bar+)+
  const nestedQuantifierRegex = /\((?:[^()]*[+*?]|[^()]*\{\d+,?\d*\})\)(?:[+*?]|(?:\{\d+,?\d*\}))/;
  if (nestedQuantifierRegex.test(pattern)) {
    return {
      safe: false,
      reason: 'ReDoS Vulnerability: Nested quantifiers with catastrophic backtracking risk detected (e.g. (a+)+ or (.*)*).',
    };
  }

  // 3. Reject groups with multiple internal repetitions under an outer quantifier: ((a+)(b+))+
  const multiQuantifiedGroup = /\((?:[^()]*[+*]){2,}[^()]*\)[+*]/;
  if (multiQuantifiedGroup.test(pattern)) {
    return {
      safe: false,
      reason: 'ReDoS Vulnerability: Group contains multiple repeated tokens inside a quantifier.',
    };
  }

  // 4. Reject adjacent/overlapping wildcards: .*.* or .+.+ or (.*){2,}
  if (/(?:\.\*|\.\+){2,}/.test(pattern) || /\(\.\*\)\{\d+,?\}/.test(pattern)) {
    return {
      safe: false,
      reason: 'ReDoS Vulnerability: Overlapping wildcard repetitions detected (e.g. .*.* or (.*){2,}).',
    };
  }

  // 5. Reject excessively large repetition bounds (> 500 repetitions)
  const largeBound = /\{(\d+)(?:,(\d*))?\}/g;
  let match;
  while ((match = largeBound.exec(pattern)) !== null) {
    const min = parseInt(match[1], 10);
    const max = match[2] ? parseInt(match[2], 10) : min;
    if (min > 500 || max > 500) {
      return {
        safe: false,
        reason: 'ReDoS Vulnerability: Quantifier repetition bound exceeds safe threshold (max 500 repetitions allowed).',
      };
    }
  }

  // 6. Reject overlapping alternations with outer repetition: (a|aa)+ or (x|xx)+
  const altMatch = /\(([a-zA-Z0-9_]+)\|([a-zA-Z0-9_]+)\)[+*]/.exec(pattern);
  if (altMatch) {
    const [, opt1, opt2] = altMatch;
    if (opt1.startsWith(opt2) || opt2.startsWith(opt1)) {
      return {
        safe: false,
        reason: 'ReDoS Vulnerability: Ambiguous overlapping alternation with outer repetition detected.',
      };
    }
  }

  return { safe: true };
}
