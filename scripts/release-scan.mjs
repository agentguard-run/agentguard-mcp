#!/usr/bin/env node
/** Scan only explicit MCP release files. Findings contain file names and rule IDs. */
import {execFile} from 'node:child_process';
import {lstat, readFile} from 'node:fs/promises';
import {dirname, isAbsolute, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';

const execute = promisify(execFile);
export const APPROVED_PUBLIC_FILES = Object.freeze([
  '.gitignore', 'CHANGELOG.md', 'LICENSE', 'README.md', 'docs/mcp-registry.md',
  'package-lock.json', 'package.json', 'scripts/public-files.json', 'scripts/release-scan.mjs',
  'server.json', 'src/index.ts', 'src/stdio-transport.ts', 'test/release-metadata.test.mjs',
  'test/release-scan.test.mjs', 'test/smoke.mjs', 'tsconfig.json',
]);
export const APPROVED_PACK_FILES = Object.freeze([
  'CHANGELOG.md', 'LICENSE', 'README.md', 'package.json', 'server.json',
  'dist/index.js', 'dist/index.d.ts', 'dist/stdio-transport.js', 'dist/stdio-transport.d.ts',
]);
const CONTENT_RULES = [
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/],
  ['provider-credential', /\b(?:sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{24,}|[sr]k_(?:live|test)_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{30,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35})\b/],
  ['literal-credential', /["']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|privateKeyHex)["']?\s*[:=]\s*["'][A-Za-z0-9+/_=-]{20,}["']/i],
  ['bearer-credential', /\bBearer\s+[A-Za-z0-9._~+\/-]{24,}/i],
  ['credential-url', /https?:\/\/[^\s/:'"<>]+:[^\s/@'"<>]+@/i],
  ['private-path', /(?:\/Users\/[^\s'"`<>]+|\/home\/[^\s'"`<>]+|\/private\/(?:tmp|var)\/[^\s'"`<>]+|[A-Z]:\\Users\\[^\s'"`<>]+)/],
  ['patent-disclosure', /(?:^|\n)\s*(?:what is claimed is|field of the invention|background of the invention|summary of the invention|detailed description of the invention|claims)\s*[:.\r\n]/i],
  ['patent-filing', /(?:application\s+(?:number|serial\s+no\.?):\s*\d{2}\/\d{3}[, ]?\d{3}|confidential\s+invention\s+disclosure)/i],
  ['patent-number', /\b(?:(?:U\.?S\.?\s*(?:patent\s*(?:application\s*)?(?:no\.?|number)?\s*)?|patent\s+(?:no\.?|number)?\s*)(?:\d{4}[ /-]?\d{7}|\d{1,3},\d{3},\d{3}|\d{7,8})(?:\s*[AB]\d)?|(?:WO|PCT)[ /]*(?:[A-Z]{2})?\s*\d{4}[ /-]\d{6}|EP\s*\d{7}(?:\s*[AB]\d)?|\d{2}\/\d{3},?\d{3})\b/i],
  ['docket-identifier', /\b(?:attorney(?:'s)?\s+)?docket(?:\s+(?:no\.?|number|id|identifier))?\s*[:#]\s*[A-Z0-9][A-Z0-9._/-]{2,}\b|\bdocket\s+(?:no\.?|number|id)\s+[A-Z0-9._/-]*\d[A-Z0-9._/-]*\b/i],
  ['phone-number', /(?<![\w])(?:\+?1[ .-]?)?(?:\([2-9]\d{2}\)[ .-]?|[2-9]\d{2}[ .-])[2-9]\d{2}[ .-]\d{4}(?!\d)|(?<![\w])\+[1-9]\d{0,2}[ .-](?:\d[ .-]?){7,13}\d(?!\d)|(?<![\w])(?:\+[1-9]\d{7,14}|1?[2-9]\d{2}[2-9]\d{6})(?![\w])|\btel:\s*\+?\d[\d .()-]{7,}\d\b/i],
  ['unfiled-mark', /\u2122|\u2120|\((?:TM|SM)\)/i],
];
const FILE_LIMIT = 5 * 1024 * 1024;
function displayFile(file) {return String(file).replace(/[\u0000-\u001f\u007f]/g, '?').slice(0, 240);}
function safeRelative(file) {
  return typeof file === 'string' && file.length > 0 && !isAbsolute(file)
    && !/[\\\u0000-\u001f\u007f]/.test(file) && !/^[a-z]:/i.test(file)
    && file.split('/').every(part => part && part !== '.' && part !== '..');
}
function withoutSyntheticFixtureValues(file, content) {
  if (file !== 'test/smoke.mjs') return content;
  // These exact rejection-test sentinels predate this scanner. Other test values are scanned.
  const values = [
    ['sk-proj-', 'MCP_SECRET_SENTINEL_7042'].join(''),
    ['/', 'Users/private-customer/Documents/secret-model.gguf'].join(''),
    ['/', 'Users/private/model'].join(''),
  ];
  return values.reduce((text, value) => {
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return text.replace(new RegExp(escaped + '(?=$|[\\s\'"`<>])', 'g'), '[synthetic-fixture]');
  }, content);
}
function withoutFiledLicenseNotice(file, content) {
  if (file !== 'LICENSE') return content;
  // Preserve the existing legal notice for the expressly filed mark. This exact
  // notice is the only marker exception, in LICENSE only. Patent reservations
  // contain no filing numbers or disclosure text and need no content exemption.
  const notice = [
    'MerchantGuard(', 'TM) is a trademark of Dunecrest\n',
    'Ventures Inc. (USPTO Serial No. ', '99051215, pending).',
  ].join('');
  return content.replace(notice, '[existing filed-mark license notice]');
}
export function scanContent(file, content) {
  const text = withoutFiledLicenseNotice(file, withoutSyntheticFixtureValues(file, content));
  const findings = CONTENT_RULES.filter(([, expression]) => expression.test(text)).map(([rule]) => ({file: displayFile(file), rule}));
  if (file === 'package.json' || file === 'package-lock.json') {
    try {
      const data = JSON.parse(content);
      const dependencies = {...data.dependencies, ...data.devDependencies, ...data.optionalDependencies};
      const local = value => typeof value === 'string' && /^(?:file:|link:|workspace:|\.\.?[\/\\]|[\/\\])/.test(value);
      if (Object.values(dependencies).some(local)
        || Object.entries(data.packages || {}).some(([name, entry]) => local(name) || entry?.link === true || local(entry?.resolved))) {
        findings.push({file, rule: 'local-dependency'});
      }
    } catch {findings.push({file, rule: 'invalid-package-json'});}
  }
  return findings;
}
async function inspectFile(root, file) {
  const findings = [];
  if (!safeRelative(file)) return [{file: displayFile(file), rule: 'unsafe-path'}];
  const parts = file.split('/'); let current = root;
  for (let index = 0; index < parts.length; index++) {
    current = join(current, parts[index]);
    let info;
    try {info = await lstat(current);} catch {return [{file, rule: 'missing-or-unreadable-file'}];}
    if (info.isSymbolicLink()) return [{file, rule: 'symlink'}];
    if (index < parts.length - 1 && !info.isDirectory()) return [{file, rule: 'non-directory-parent'}];
    if (index === parts.length - 1) {
      if (!info.isFile()) return [{file, rule: 'not-regular-file'}];
      if (info.size > FILE_LIMIT) return [{file, rule: 'oversized-file'}];
    }
  }
  try {
    const bytes = await readFile(current);
    if (bytes.includes(0)) findings.push({file, rule: 'binary-file'});
    else findings.push(...scanContent(file, bytes.toString('utf8')));
  } catch {findings.push({file, rule: 'missing-or-unreadable-file'});}
  return findings;
}
export async function readPublicFiles(root) {
  const source = join(root, 'scripts/public-files.json');
  const info = await lstat(source);
  if (info.isSymbolicLink() || !info.isFile() || info.size > FILE_LIMIT) throw new Error('invalid-public-file-list');
  const manifest = JSON.parse(await readFile(source, 'utf8'));
  if (manifest.version !== 1 || !Array.isArray(manifest.files)) throw new Error('invalid-public-file-list');
  return manifest.files;
}
export async function dryRunPack(root, run = execute) {
  // Ignore lifecycle scripts to prevent prepublish recursion or user-configured build side effects.
  const {stdout} = await run('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: root, timeout: 30_000, maxBuffer: 8 * 1024 * 1024,
    env: {...process.env, npm_config_ignore_scripts: 'true', npm_config_audit: 'false', npm_config_fund: 'false', npm_config_update_notifier: 'false'},
  });
  const result = JSON.parse(stdout);
  if (!Array.isArray(result) || result.length !== 1 || !Array.isArray(result[0]?.files)) throw new Error('invalid-pack-file-list');
  return result[0].files.map(entry => entry.path);
}
export async function scanRelease({root, packFiles, publicFiles}) {
  const base = resolve(root), findings = [], files = new Set();
  for (const [list, approved, kind] of [[packFiles, APPROVED_PACK_FILES, 'tarball'], [publicFiles, APPROVED_PUBLIC_FILES, 'public-mirror']]) {
    if (!Array.isArray(list) || list.length > 1000) {findings.push({file: 'package.json', rule: `invalid-${kind}-file-list`}); continue;}
    const seen = new Set();
    for (const file of list) {
      if (!safeRelative(file)) {findings.push({file: displayFile(file), rule: 'unsafe-path'}); continue;}
      if (!approved.includes(file)) {findings.push({file, rule: `unexpected-${kind}-file`}); continue;}
      if (seen.has(file)) findings.push({file, rule: `duplicate-${kind}-file`});
      seen.add(file); files.add(file);
    }
    for (const required of approved) if (!seen.has(required)) findings.push({file: required, rule: `missing-${kind}-file`});
  }
  for (const file of [...files].sort()) findings.push(...await inspectFile(base, file));
  const unique = [...new Map(findings.map(finding => [`${finding.file}\0${finding.rule}`, finding])).values()];
  return {ok: unique.length === 0, packFileCount: Array.isArray(packFiles) ? packFiles.length : 0,
    publicFileCount: Array.isArray(publicFiles) ? publicFiles.length : 0, findings: unique};
}
export async function main(root = resolve(dirname(fileURLToPath(import.meta.url)), '..')) {
  let publicFiles, packFiles;
  try {publicFiles = await readPublicFiles(root);} catch {
    process.stderr.write('scripts/public-files.json: invalid-public-file-list\n'); return 1;
  }
  try {packFiles = await dryRunPack(root);} catch {
    process.stderr.write('package.json: npm-pack-dry-run-failed\n'); return 1;
  }
  const result = await scanRelease({root, packFiles, publicFiles});
  if (!result.ok) {
    for (const {file, rule} of result.findings) process.stderr.write(`${displayFile(file)}: ${rule}\n`);
    return 1;
  }
  process.stdout.write(`Release scan passed: ${result.packFileCount} npm files; ${result.publicFileCount} public mirror files.\n`);
  return 0;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {process.exitCode = await main();} catch {
    process.stderr.write('package.json: release-scan-failed\n'); process.exitCode = 1;
  }
}
