import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, rm, symlink, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {test} from 'node:test';
import {APPROVED_PACK_FILES, APPROVED_PUBLIC_FILES, dryRunPack, readPublicFiles, scanContent, scanRelease} from '../scripts/release-scan.mjs';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'ag-mcp-release-scan-'));
  t.after(() => rm(root, {recursive: true, force: true}));
  for (const file of new Set([...APPROVED_PACK_FILES, ...APPROVED_PUBLIC_FILES])) {
    await mkdir(dirname(join(root, file)), {recursive: true}); await writeFile(join(root, file), 'Public package fixture.\n');
  }
  await writeFile(join(root, 'scripts/public-files.json'), JSON.stringify({version: 1, files: APPROVED_PUBLIC_FILES}));
  await writeFile(join(root, 'package.json'), JSON.stringify({name: '@agentguard-run/mcp', version: '0.3.0'}));
  await writeFile(join(root, 'package-lock.json'), JSON.stringify({name: '@agentguard-run/mcp', version: '0.3.0', packages: {}}));
  return {root, packFiles: [...APPROVED_PACK_FILES], publicFiles: [...APPROVED_PUBLIC_FILES]};
}

test('explicit public mirror list contains only this package source and release support', async () => {
  assert.deepEqual(await readPublicFiles(packageRoot), APPROVED_PUBLIC_FILES);
  assert.ok(APPROVED_PUBLIC_FILES.includes('LICENSE'));
  assert.ok(!APPROVED_PUBLIC_FILES.some(file => file.startsWith('dist/') || file.includes('node_modules') || file.startsWith('packages/')));
});

test('current built MCP package passes tarball and public source content checks', async () => {
  const result = await scanRelease({root: packageRoot, packFiles: APPROVED_PACK_FILES, publicFiles: await readPublicFiles(packageRoot)});
  assert.deepEqual(result.findings, []); assert.equal(result.ok, true);
});

test('dry-run collection disables lifecycle scripts and extracts exact npm pack paths', async () => {
  const calls = [];
  const paths = await dryRunPack(packageRoot, async (...args) => {
    calls.push(args); return {stdout: JSON.stringify([{files: APPROVED_PACK_FILES.map(path => ({path, size: 1}))}])};
  });
  assert.deepEqual(paths, APPROVED_PACK_FILES);
  assert.equal(calls[0][0], 'npm');
  assert.deepEqual(calls[0][1], ['pack', '--dry-run', '--json', '--ignore-scripts']);
  assert.equal(calls[0][2].cwd, packageRoot); assert.equal(calls[0][2].env.npm_config_ignore_scripts, 'true');
  assert.ok(calls[0][2].timeout <= 30000);
  await assert.rejects(dryRunPack(packageRoot, async () => ({stdout: '{}'})), /invalid-pack-file-list/);
});

test('unexpected tarball content and expanded public mirror files are refused', async t => {
  const input = await fixture(t);
  input.packFiles.push('dist/debug-secrets.json');
  input.publicFiles.push('packages/agentguard-spend/src/index.ts');
  const result = await scanRelease(input);
  assert.equal(result.ok, false);
  assert.deepEqual(result.findings, [
    {file: 'dist/debug-secrets.json', rule: 'unexpected-tarball-file'},
    {file: 'packages/agentguard-spend/src/index.ts', rule: 'unexpected-public-mirror-file'},
  ]);
});

test('relative traversal, absolute paths and malformed path separators are never read', async t => {
  const input = await fixture(t);
  for (const path of ['../outside', '/etc/passwd', 'src/../../outside', 'src\\index.ts', 'src//index.ts', './README.md', 'C:\\outside']) {
    const result = await scanRelease({...input, packFiles: [...input.packFiles, path]});
    assert.ok(result.findings.some(finding => finding.rule === 'unsafe-path'));
    assert.ok(result.findings.every(finding => !finding.rule.includes('unreadable')));
  }
});

test('missing required files and duplicate allowlist entries cannot pass', async t => {
  const input = await fixture(t);
  const missing = await scanRelease({...input, publicFiles: input.publicFiles.filter(file => file !== 'LICENSE')});
  assert.ok(missing.findings.some(finding => finding.file === 'LICENSE' && finding.rule === 'missing-public-mirror-file'));
  const duplicate = await scanRelease({...input, publicFiles: [...input.publicFiles, 'LICENSE']});
  assert.ok(duplicate.findings.some(finding => finding.rule === 'duplicate-public-mirror-file'));
  await rm(join(input.root, 'README.md'));
  assert.ok((await scanRelease(input)).findings.some(finding => finding.file === 'README.md' && finding.rule === 'missing-or-unreadable-file'));
});

test('file and parent-directory symlinks fail before their target content is read', async t => {
  const input = await fixture(t), target = join(input.root, 'outside');
  await writeFile(target, ['sk-', 'a'.repeat(40)].join(''));
  await rm(join(input.root, 'README.md')); await symlink(target, join(input.root, 'README.md'));
  let result = await scanRelease(input);
  assert.deepEqual(result.findings, [{file: 'README.md', rule: 'symlink'}]);
  await rm(join(input.root, 'README.md')); await writeFile(join(input.root, 'README.md'), 'Safe.');
  await rm(join(input.root, 'src'), {recursive: true}); await symlink(dirname(target), join(input.root, 'src'));
  result = await scanRelease(input);
  assert.ok(result.findings.filter(finding => finding.rule === 'symlink').length === 2);
  assert.ok(result.findings.every(finding => finding.rule !== 'provider-credential'));
});

test('credential and private-path findings contain file and rule only, never the matched content', async t => {
  const input = await fixture(t);
  const token = ['npm_', 'a'.repeat(36)].join('');
  const privatePath = ['/', 'Users/customer-real-account/restricted/report.txt'].join('');
  await writeFile(join(input.root, 'README.md'), `${token}\n${privatePath}\n`);
  const result = await scanRelease(input), output = JSON.stringify(result);
  assert.ok(result.findings.some(finding => finding.rule === 'provider-credential'));
  assert.ok(result.findings.some(finding => finding.rule === 'private-path'));
  assert.ok(!output.includes(token)); assert.ok(!output.includes(privatePath));
  assert.ok(result.findings.every(finding => Object.keys(finding).sort().join(',') === 'file,rule'));
});

test('literal credentials, private keys and credential-bearing URLs are rejected', () => {
  const examples = [
    ['private-key', ['-----BEGIN ', 'PRIVATE KEY-----'].join('')],
    ['literal-credential', ['api_key = "', 'x'.repeat(32), '"'].join('')],
    ['credential-url', ['https:', '//user:credential-value@example.invalid'].join('')],
  ];
  for (const [rule, content] of examples) assert.ok(scanContent('src/index.ts', content).some(finding => finding.rule === rule));
});

test('only exact existing smoke sentinels are exempt, and no exemption reaches other files', () => {
  const synthetic = ['sk-proj-', 'MCP_SECRET_SENTINEL_7042'].join('');
  const syntheticPath = ['/', 'Users/private-customer/Documents/secret-model.gguf'].join('');
  assert.deepEqual(scanContent('test/smoke.mjs', `${synthetic}\n${syntheticPath}`), []);
  assert.ok(scanContent('README.md', syntheticPath).some(finding => finding.rule === 'private-path'));
  assert.ok(scanContent('test/smoke.mjs', syntheticPath + '.backup').some(finding => finding.rule === 'private-path'));
  assert.ok(scanContent('test/smoke.mjs', synthetic + 'EXTRA').some(finding => finding.rule === 'provider-credential'));
  assert.ok(scanContent('test/smoke.mjs', ['sk-proj-', 'z'.repeat(40)].join('')).some(finding => finding.rule === 'provider-credential'));
});

test('existing public LICENSE patent reservations are retained while invention disclosures are rejected', async () => {
  const license = await readFile(join(packageRoot, 'LICENSE'), 'utf8');
  assert.match(license, /NO PATENT LICENSE GRANTED/);
  assert.match(license, /All patent rights are expressly reserved/);
  assert.deepEqual(scanContent('LICENSE', license), []);
  const disclosure = ['FIELD OF THE ', 'INVENTION:\nPrivate technical detail.'].join('');
  assert.ok(scanContent('README.md', disclosure).some(finding => finding.rule === 'patent-disclosure'));
  assert.ok(scanContent('LICENSE', disclosure).some(finding => finding.rule === 'patent-disclosure'));
});

test('patent application and grant numbers, docket identifiers and phone numbers block the release', () => {
  const examples = [
    ['patent-number', ['US ', '12,345,678 B2'].join('')],
    ['patent-number', ['U.S. Patent No. ', '12,345,678'].join('')],
    ['patent-number', ['Patent number ', '12,345,678'].join('')],
    ['patent-number', ['US', '2026', '0123456', 'A1'].join('')],
    ['patent-number', ['WO ', '2026/', '123456'].join('')],
    ['patent-number', ['PCT/US', '2026/', '123456'].join('')],
    ['patent-number', ['EP ', '1234567 B1'].join('')],
    ['patent-number', ['63/', '123,456'].join('')],
    ['docket-identifier', ['Attorney docket: ', 'EXAMPLE-2026-001'].join('')],
    ['docket-identifier', ['Docket No. ', 'EXAMPLE-2026-001'].join('')],
    ['phone-number', ['+1 ', '202-', '555-', '0123'].join('')],
    ['phone-number', ['(', '202) ', '555-', '0123'].join('')],
    ['phone-number', ['+44 ', '20 ', '7946 ', '0958'].join('')],
    ['phone-number', ['tel:', '+1202', '5550123'].join('')],
    ['phone-number', ['+1202', '5550123'].join('')],
    ['phone-number', ['202', '5550123'].join('')],
  ];
  for (const [rule, content] of examples) {
    const findings = scanContent('README.md', content);
    assert.ok(findings.some(finding => finding.rule === rule), rule);
    assert.ok(!JSON.stringify(findings).includes(content));
    assert.ok(scanContent('LICENSE', content).some(finding => finding.rule === rule), `LICENSE ${rule}`);
  }
});

test('unfiled trademark and service-mark markers block even synthetic product names', () => {
  for (const marker of [String.fromCodePoint(0x2122), String.fromCodePoint(0x2120), ['(', 'TM)'].join(''), ['(', 'sm)'].join('')]) {
    const findings = scanContent('README.md', `Example ${marker}`);
    assert.deepEqual(findings, [{file: 'README.md', rule: 'unfiled-mark'}]);
  }
  assert.deepEqual(scanContent('README.md', 'AgentGuard(R) is a registered trademark. Files named timestamp.ts are public.'), []);
});

test('the exact filed LICENSE notice is the only mark-marker exception and cannot hide added content', async () => {
  const license = await readFile(join(packageRoot, 'LICENSE'), 'utf8');
  assert.deepEqual(scanContent('LICENSE', license), []);
  assert.ok(scanContent('README.md', license).some(finding => finding.rule === 'unfiled-mark'));
  const changed = license.replace('99051215', '00000000');
  assert.ok(scanContent('LICENSE', changed).some(finding => finding.rule === 'unfiled-mark'));
  assert.ok(scanContent('LICENSE', `${license}\nPrivateProduct${String.fromCodePoint(0x2122)}`).some(finding => finding.rule === 'unfiled-mark'));
});

test('release dates, versions, hashes, registry URLs and patent-rights language do not resemble protected identifiers', () => {
  const text = [
    '2026-09-21T12:34:56.000Z', '@agentguard-run/mcp 0.3.1',
    'https://registry.modelcontextprotocol.io/v0.1/servers',
    'a'.repeat(64), 'Copyright (c) 2026 Dunecrest Ventures Inc.',
    'All patent rights are expressly reserved. Nothing grants a patent license.',
    'Reject patent numbers, docket identifiers, phone numbers and unfiled marks.',
    'support@example.invalid', '35 U.S.C. section 287',
  ].join('\n');
  assert.deepEqual(scanContent('README.md', text), []);
});

test('local dependency links cannot leak into release manifests or lockfiles', () => {
  assert.deepEqual(scanContent('package.json', JSON.stringify({dependencies: {spend: '^0.19.0'}})), []);
  for (const version of ['file:../agentguard-spend', 'link:../agentguard-spend', 'workspace:*']) {
    assert.deepEqual(scanContent('package.json', JSON.stringify({dependencies: {spend: version}})), [{file: 'package.json', rule: 'local-dependency'}]);
  }
  const lock = {packages: {'node_modules/spend': {resolved: '../agentguard-spend', link: true}}};
  assert.deepEqual(scanContent('package-lock.json', JSON.stringify(lock)), [{file: 'package-lock.json', rule: 'local-dependency'}]);
});
