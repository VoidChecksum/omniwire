import test from 'node:test';
import assert from 'node:assert/strict';

import {
  describeEnvValue,
  formatEnvKeyListing,
  isSensitiveKey,
  isValidEnvKey,
} from '../dist/security/redaction.js';

test('validates shell-safe environment variable names', () => {
  assert.equal(isValidEnvKey('OP_SERVICE_ACCOUNT_TOKEN'), true);
  assert.equal(isValidEnvKey('_OMNIWIRE_1'), true);
  assert.equal(isValidEnvKey('1BAD'), false);
  assert.equal(isValidEnvKey('BAD-NAME'), false);
  assert.equal(isValidEnvKey('BAD;rm -rf /'), false);
});

test('classifies sensitive environment keys', () => {
  assert.equal(isSensitiveKey('OP_SERVICE_ACCOUNT_TOKEN'), true);
  assert.equal(isSensitiveKey('DATABASE_PASSWORD'), true);
  assert.equal(isSensitiveKey('PUBLIC_PORT'), false);
});

test('formats environment listings without exposing values', () => {
  const output = formatEnvKeyListing(['PUBLIC_PORT', 'OP_SERVICE_ACCOUNT_TOKEN', 'BAD-NAME']);
  assert.match(output, /OP_SERVICE_ACCOUNT_TOKEN=<redacted>/);
  assert.match(output, /PUBLIC_PORT=<set>/);
  assert.doesNotMatch(output, /BAD-NAME/);
});

test('describes values without echoing secret material', () => {
  assert.equal(describeEnvValue('super-secret-token'), '<redacted: set>');
  assert.equal(describeEnvValue(''), '(unset)');
  assert.equal(describeEnvValue(null), '(unset)');
});
