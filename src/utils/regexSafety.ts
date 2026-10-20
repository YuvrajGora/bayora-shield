/**
 * Bayora Shield — Safe Regex Evaluation Engine (SEC-04)
 *
 * Provides static pattern safety analysis and ReDoS mitigation.
 * Implements token-aware parenthesis analysis to reject catastrophic
 * backtracking patterns, nested quantifiers, repeated alternations,
 * and dangerous quantifier repetition bounds.
 *
 * DEFENSIVE NOTE: Static analysis is a defense-in-depth pre-filter and does NOT
 * guarantee universal safety for all theoretical regexes. Bounded runtime execution
 * (e.g. 100ms V8 VM sandbox timeout) remains mandatory as the primary execution guard.
 */

export interface RegexSafetyResult {
  safe: boolean;
  reason?: string;
}

interface GroupNode {
  parent?: GroupNode;
  hasInnerQuantifier: boolean;
  currentBranch: string;
  branches: string[];
}

/**
 * Validates a regular expression pattern against known ReDoS anti-patterns.
 * Uses a token-aware parser to inspect nested parentheses, repetition bounds,
 * overlapping alternations, and catastrophic backtracking risks.
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

  // 2. Reject excessively large repetition bounds (> 500 repetitions)
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

  // 3. Reject adjacent/overlapping wildcards: .*.* or .+.+ or (.*){2,}
  if (/(?:\.\*|\.\+){2,}/.test(pattern) || /\(\.\*\)\{\d+,?\}/.test(pattern)) {
    return {
      safe: false,
      reason: 'ReDoS Vulnerability: Overlapping wildcard repetitions detected (e.g. .*.* or (.*){2,}).',
    };
  }

  // 4. Token-aware nested quantifier & group structure parser
  // Accurately tracks parenthesized groups across arbitrary nesting depth
  const rootGroup: GroupNode = {
    hasInnerQuantifier: false,
    currentBranch: '',
    branches: [],
  };

  const stack: GroupNode[] = [rootGroup];
  let i = 0;
  const len = pattern.length;

  while (i < len) {
    const char = pattern[i];
    const current = stack[stack.length - 1];

    if (char === '\\') {
      // Escaped character: skip backslash and next char
      current.currentBranch += pattern.substring(i, Math.min(i + 2, len));
      i += 2;
      continue;
    }

    if (char === '[') {
      // Character class: scan until unescaped ']'
      let j = i + 1;
      if (j < len && (pattern[j] === ']' || pattern[j] === '^')) {
        j++; // handle '[]...]' or '[^]...]'
      }
      while (j < len && pattern[j] !== ']') {
        if (pattern[j] === '\\') j += 2;
        else j++;
      }
      const classStr = pattern.substring(i, Math.min(j + 1, len));
      current.currentBranch += classStr;
      i = j + 1;

      // Check if character class is quantified directly (e.g. [a-z]+)
      if (i < len && (pattern[i] === '+' || pattern[i] === '*')) {
        current.hasInnerQuantifier = true;
        current.currentBranch += pattern[i];
        i++;
      } else if (i < len && pattern[i] === '{') {
        const boundMatch = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.substring(i));
        if (boundMatch) {
          const min = parseInt(boundMatch[1], 10);
          if (min > 1 || boundMatch[2] !== undefined) {
            current.hasInnerQuantifier = true;
          }
          current.currentBranch += boundMatch[0];
          i += boundMatch[0].length;
        }
      }
      continue;
    }

    if (char === '(') {
      // Begin new group
      let isNonCapturing = false;
      if (pattern.startsWith('(?:', i)) {
        isNonCapturing = true;
        i += 3;
      } else {
        i += 1;
      }

      const newGroup: GroupNode = {
        parent: current,
        hasInnerQuantifier: false,
        currentBranch: '',
        branches: [],
      };
      stack.push(newGroup);
      continue;
    }

    if (char === '|') {
      // Alternation branch inside current group
      current.branches.push(current.currentBranch.trim());
      current.currentBranch = '';
      i++;
      continue;
    }

    if (char === ')') {
      // Closing group
      if (stack.length > 1) {
        const closedGroup = stack.pop()!;
        closedGroup.branches.push(closedGroup.currentBranch.trim());
        const parent = stack[stack.length - 1];

        // Lookahead to inspect quantifier on this closed group
        let isQuantified = false;
        let isRepetitionQuantifier = false;
        let quantifierLength = 0;

        let k = i + 1;
        if (k < len) {
          if (pattern[k] === '+' || pattern[k] === '*') {
            isQuantified = true;
            isRepetitionQuantifier = true;
            quantifierLength = 1;
            // Handle optional lazy / possessive modifiers: *?, ++, etc.
            if (k + 1 < len && (pattern[k + 1] === '?' || pattern[k + 1] === '+')) {
              quantifierLength = 2;
            }
          } else if (pattern[k] === '?') {
            isQuantified = true;
            quantifierLength = 1;
          } else if (pattern[k] === '{') {
            const bMatch = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.substring(k));
            if (bMatch) {
              isQuantified = true;
              const min = parseInt(bMatch[1], 10);
              const max = bMatch[2] ? parseInt(bMatch[2], 10) : min;
              if (min > 1 || max > 1) {
                isRepetitionQuantifier = true;
              }
              quantifierLength = bMatch[0].length;
            }
          }
        }

        if (isRepetitionQuantifier) {
          // Rule A: Nested quantifier — inner repeated token or group under an outer repetition quantifier
          if (closedGroup.hasInnerQuantifier) {
            return {
              safe: false,
              reason: 'ReDoS Vulnerability: Nested quantifiers detected with catastrophic backtracking risk (e.g. ((a+))+ or (a|b+)+).',
            };
          }

          // Rule B: Overlapping alternation branches under repetition (e.g. (a|aa)+ or (user|username)*)
          const validBranches = closedGroup.branches.filter((b) => b.length > 0);
          if (validBranches.length > 1) {
            for (let m = 0; m < validBranches.length; m++) {
              for (let n = m + 1; n < validBranches.length; n++) {
                const b1 = validBranches[m];
                const b2 = validBranches[n];
                // Check if one branch is a prefix/suffix of another or shares identical leading token
                if (b1.length > 0 && b2.length > 0 && (b1.startsWith(b2) || b2.startsWith(b1))) {
                  return {
                    safe: false,
                    reason: `ReDoS Vulnerability: Overlapping alternation branches ("${b1}" and "${b2}") under repetition quantifier.`,
                  };
                }
              }
            }
          }

          // Since this group itself is repeated, mark the parent as having an inner quantifier
          parent.hasInnerQuantifier = true;
        } else if (closedGroup.hasInnerQuantifier) {
          // If group had inner quantifier, bubble up to parent even if not outer-quantified
          parent.hasInnerQuantifier = true;
        }

        i += 1 + quantifierLength;
        continue;
      }
    }

    if (char === '+' || char === '*') {
      // Repetition on previous token outside group closing
      current.hasInnerQuantifier = true;
    }

    current.currentBranch += char;
    i++;
  }

  return { safe: true };
}
