// Extract project context (description, tags, slug) from a project directory.
//
// Used by setup.js to auto-derive an agent's expertise without asking the user.
// Reads CLAUDE.md, README.md, and language manifests (package.json, Cargo.toml,
// pyproject.toml, build.gradle.kts, go.mod, pom.xml, ...).
//
// Node 20+ stdlib only.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MAX_DESCRIPTION = 500;
const MAX_PROJECT_DESCRIPTION = 1500;
const MAX_TAGS = 10;
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'build', 'dist', 'target',
  '__pycache__', '.gradle', '.venv', 'venv',
]);

function extract(root) {
  const abs = path.resolve(root);
  const rawName = path.basename(abs);
  const name = slug(rawName) || 'agent';

  let projectDescription = '';
  const tags = new Set();

  // CLAUDE.md — preferred since it's curated for AI consumption
  const claudeMd = readFile(path.join(abs, 'CLAUDE.md'));
  if (claudeMd) {
    const para = firstParagraph(claudeMd);
    if (para) projectDescription = para;
  }

  // README.md — fallback or supplementary
  const readme = readFile(path.join(abs, 'README.md'));
  if (readme) {
    const para = firstParagraph(readme);
    if (para && !projectDescription) projectDescription = para;
  }

  // package.json
  const pkgJson = readFile(path.join(abs, 'package.json'));
  if (pkgJson) {
    tags.add('javascript');
    if (isFile(path.join(abs, 'tsconfig.json'))) tags.add('typescript');
    try {
      const data = JSON.parse(pkgJson);
      if (data && typeof data === 'object') {
        if (!projectDescription && typeof data.description === 'string') {
          projectDescription = data.description;
        }
        const deps = Object.assign(
          {},
          data.dependencies || {},
          data.devDependencies || {},
        );
        for (const dep of Object.keys(deps)) {
          if (dep === 'react') tags.add('react');
          else if (dep === 'next') tags.add('nextjs');
          else if (dep === 'vue') tags.add('vue');
          else if (dep.startsWith('@angular/')) tags.add('angular');
          else if (dep === 'express') tags.add('express');
          else if (dep === 'fastify') tags.add('fastify');
        }
      }
    } catch (_) { /* ignore */ }
  }

  // Rust
  const cargo = readFile(path.join(abs, 'Cargo.toml'));
  if (cargo) {
    tags.add('rust');
    const m = cargo.match(/^\s*description\s*=\s*"([^"]+)"/m);
    if (m && !projectDescription) projectDescription = m[1];
  }

  // Python
  const pyproject = readFile(path.join(abs, 'pyproject.toml'));
  if (
    pyproject
    || isFile(path.join(abs, 'setup.py'))
    || isFile(path.join(abs, 'requirements.txt'))
  ) {
    tags.add('python');
    if (pyproject) {
      const m = pyproject.match(/^\s*description\s*=\s*"([^"]+)"/m);
      if (m && !projectDescription) projectDescription = m[1];
    }
  }

  // Go
  if (isFile(path.join(abs, 'go.mod'))) tags.add('go');

  // JVM / Gradle / Maven
  const hasGradle = [
    'build.gradle.kts', 'build.gradle',
    'settings.gradle.kts', 'settings.gradle',
  ].some((f) => isFile(path.join(abs, f)));
  if (hasGradle) tags.add('gradle');
  if (isFile(path.join(abs, 'pom.xml'))) {
    tags.add('maven');
    tags.add('java');
  }

  // Kotlin / Java detection by file extension (top-level + src/)
  const exts = scanExtensions(abs, 300);
  if (exts.has('.kt') || exts.has('.kts')) tags.add('kotlin');
  else if (hasGradle && exts.has('.java')) tags.add('java');
  if (exts.has('.swift')) tags.add('swift');
  if (exts.has('.rb')) tags.add('ruby');
  if (exts.has('.py')) tags.add('python');
  if (exts.has('.rs')) tags.add('rust');
  if (exts.has('.go')) tags.add('go');

  // Infra
  if (
    isFile(path.join(abs, 'Dockerfile'))
    || globAny(abs, ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'])
  ) tags.add('docker');
  if (anyTopLevelMatch(abs, (p) => p.endsWith('.tf'))) tags.add('terraform');
  if (isDir(path.join(abs, 'kubernetes')) || globAny(abs, ['k8s', 'deployment.yaml'])) {
    tags.add('kubernetes');
  }

  // Heuristic feature tags from the description
  const blob = (`${projectDescription} ${claudeMd || ''} ${readme || ''}`).toLowerCase();
  const keywordTags = [
    ['postgres', 'postgres'], ['postgresql', 'postgres'],
    ['pgvector', 'pgvector'], ['redis', 'redis'], ['kafka', 'kafka'],
    ['mcp', 'mcp'], ['ktor', 'ktor'], ['spring boot', 'spring-boot'],
    ['graphql', 'graphql'], ['grpc', 'grpc'],
    ['embedding', 'embeddings'], ['llm', 'llm'],
  ];
  for (const [kw, tag] of keywordTags) {
    if (blob.includes(kw)) tags.add(tag);
  }

  if (!projectDescription) projectDescription = `Working on ${rawName}`;

  const description = `AI agent for the ${rawName} codebase`;

  return {
    name,
    description: description.slice(0, MAX_DESCRIPTION),
    project_description: projectDescription.slice(0, MAX_PROJECT_DESCRIPTION),
    tags: [...tags].sort().slice(0, MAX_TAGS),
  };
}

function readFile(p) {
  try {
    if (!isFile(p)) return null;
    return fs.readFileSync(p, { encoding: 'utf8' });
  } catch (_) {
    return null;
  }
}

function isFile(p) {
  try { return fs.statSync(p).isFile(); } catch (_) { return false; }
}

function isDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch (_) { return false; }
}

function firstParagraph(md) {
  // Strip optional YAML front-matter (--- ... ---)
  let text = md;
  if (text.startsWith('---')) {
    const end = text.indexOf('\n---', 3);
    if (end > 0) text = text.slice(end + 4);
  }
  const paras = [];
  let buf = [];
  let inCode = false;
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (s.startsWith('```') || s.startsWith('~~~')) {
      inCode = !inCode;
      continue;
    }
    if (inCode) continue;
    if (s.startsWith('#')) {
      if (buf.length) { paras.push(buf.join(' ').trim()); buf = []; }
      if (paras.length >= 2) break;
      continue;
    }
    if (
      s.startsWith('-') || s.startsWith('*')
      || s.startsWith('>') || s.startsWith('|')
      || /^\d+\.\s/.test(s)
    ) continue;
    if (!s) {
      if (buf.length) { paras.push(buf.join(' ').trim()); buf = []; }
      if (paras.length >= 2) break;
      continue;
    }
    buf.push(s);
  }
  if (buf.length) paras.push(buf.join(' ').trim());
  return paras.slice(0, 2).filter(Boolean).join('\n\n');
}

function slug(s) {
  return s.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
}

function scanExtensions(root, maxFiles) {
  const out = new Set();
  let count = 0;
  function walk(dir) {
    if (count >= maxFiles) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (_) { return; }
    for (const e of entries) {
      if (count >= maxFiles) return;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        walk(path.join(dir, e.name));
      } else if (e.isFile()) {
        out.add(path.extname(e.name).toLowerCase());
        count += 1;
      }
    }
  }
  walk(root);
  return out;
}

function globAny(root, names) {
  return names.some((n) => fs.existsSync(path.join(root, n)));
}

function anyTopLevelMatch(root, pred) {
  try {
    return fs.readdirSync(root).some(pred);
  } catch (_) { return false; }
}

module.exports = { extract };

if (require.main === module) {
  const r = process.argv[2] || process.cwd();
  process.stdout.write(JSON.stringify(extract(r), null, 2) + '\n');
}
