// CLI tests: run the real command (through tsx, so no build is needed).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const root = join(import.meta.dirname, '..'), fx = (n: string) => join(root, 'test', 'fixtures', n);
const cli = (args: string[], input?: Buffer) => {
  const r = spawnSync(process.execPath, ['--import', 'tsx', join(root, 'src', 'cli.ts'), ...args],
    { cwd: root, input, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', PHISHBOWL_OWN_DOMAINS: '' } });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
const OWN = ['--own', 'northwind.example'];

test('exit codes follow the verdict', () => {
  assert.equal(cli([fx('example-northwind-payroll.eml'), ...OWN]).code, 3);
  assert.equal(cli([fx('p01-bec-giftcards-freemail.eml')]).code, 2);
  assert.equal(cli([fx('l08-friend-gmail-calendar.eml')]).code, 0);
  assert.equal(cli([fx('example-northwind-payroll.eml'), '--exit-zero']).code, 0);
});

test('analyse prints the verdict and key findings, defanged', () => {
  const r = cli([fx('example-northwind-payroll.eml'), ...OWN]);
  assert.match(r.out, /MALICIOUS/);
  assert.match(r.out, /Key findings/);
  assert.match(r.out, /Sent as your own domain/);
  assert.doesNotMatch(r.out, /\bhttps?:\/\//);
});

test('--all lists every check, grouped', () => {
  const r = cli([fx('l01-mailchimp-newsletter.eml'), '--all']);
  assert.match(r.out, /Sender and authentication/);
  assert.match(r.out, /Delivery route/);
  assert.match(r.out, /LIKELY LEGITIMATE/);
});

test('--json is valid and complete', () => {
  const j = JSON.parse(cli([fx('example-northwind-payroll.eml'), ...OWN, '--json']).out);
  assert.equal(j.verdict.result, 'malicious');
  assert.ok(Array.isArray(j.checks) && Array.isArray(j.indicators));
});

test('a folder gives one line per email and the worst exit code', () => {
  const r = cli([join(root, 'test', 'fixtures'), ...OWN]);
  assert.equal(r.code, 3);
  assert.match(r.out, /29 files: \d+ malicious · \d+ suspicious · \d+ likely legitimate/);
});

test('stdin', () => {
  const r = cli(['-', ...OWN], readFileSync(fx('example-northwind-payroll.eml')));
  assert.equal(r.code, 3);
  assert.match(r.out, /\(stdin\)/);
});

test('report, customer email and indicator exports', () => {
  assert.match(cli(['report', fx('example-northwind-payroll.eml'), ...OWN, '--markdown']).out, /^\*\*TLP:AMBER\*\*/);
  assert.match(cli(['report', fx('example-northwind-payroll.eml'), ...OWN, '--audience', 'staff']).out, /^TLP:CLEAR/);
  assert.match(cli(['report', fx('example-northwind-payroll.eml'), ...OWN, '--customer-email']).out, /^Subject: \[TLP:AMBER\] Security alert/);
  assert.match(cli(['iocs', fx('example-northwind-payroll.eml'), '--format', 'csv']).out, /^type,indicator,defanged,seen,notes/);
  assert.match(cli(['iocs', fx('example-threat-report.txt')]).out, /# CVE\nCVE-2024-21413/);
  const out = join(tmpdir(), 'phishbowl-cli-dash.html');
  assert.equal(cli([fx('example-northwind-payroll.eml'), ...OWN, '--html', out]).code, 3);
  assert.match(readFileSync(out, 'utf8'), /Content-Security-Policy/);
});

test('text files are read as text, and bad options are errors', () => {
  const t = cli([fx('example-threat-report.txt')]);
  assert.equal(t.code, 0);
  assert.match(t.out, /TEXT/);
  assert.equal(cli([fx('l01-mailchimp-newsletter.eml'), '--nope']).code, 1);
  assert.equal(cli(['report', fx('l01-mailchimp-newsletter.eml'), '--audience', 'boss']).code, 1);
  assert.equal(cli(['no-such-file.eml']).code, 1);
});
