const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SENSITIVE_KEY_PATTERN = /(?:SECRET|TOKEN|PASSWORD|PASS|PWD|KEY|CREDENTIAL|COOKIE|SESSION|AUTH|BEARER|PRIVATE|CERT|TOTP|OTP|OP_SERVICE_ACCOUNT)/i;

export function isValidEnvKey(key: string): boolean {
  return ENV_KEY_PATTERN.test(key);
}

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

export function describeEnvValue(value: string | null | undefined): string {
  return value && value.length > 0 ? '<redacted: set>' : '(unset)';
}

export function formatEnvKeyListing(keys: Iterable<string>): string {
  const unique = [...new Set([...keys].filter(isValidEnvKey))].sort((a, b) => a.localeCompare(b));
  if (unique.length === 0) return '(no environment keys found)';
  return unique.map((key) => `${key}=${isSensitiveKey(key) ? '<redacted>' : '<set>'}`).join('\n');
}
