// The publish workflow triggers on an allowlist of image-content paths. That
// list is a hand-maintained copy of what the Dockerfile COPYs, and the two live
// in different files in different languages — so they can drift, and the drift
// is SILENT in the dangerous direction: add a COPY without updating the
// workflow and pushing that code publishes nothing, which looks exactly like a
// successful merge until the box is found running last week's image.
//
// GitHub Actions cannot read the Dockerfile, so the duplication is forced. This
// test is the joint. It fails differently from what it checks: the workflow's
// own behaviour is "did a run start", which is unobservable from here, while
// this compares the two declarations directly.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (name) =>
  readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');

// `COPY a b ./dest` — every token but the last is a source.
function dockerfileCopySources(dockerfile) {
  return dockerfile
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => /^COPY\s/i.test(l))
    .flatMap((l) => {
      const tokens = l.split(/\s+/).slice(1).filter((t) => !t.startsWith('--'));
      return tokens.slice(0, -1);
    })
    // `package-lock.json*` is a glob for "if present"; the path it names is the
    // literal file.
    .map((t) => t.replace(/\*+$/, ''))
    .filter((t) => t && t !== '.' && t !== './');
}

// The `paths:` list under `on.push`. Deliberately a small line scanner rather
// than a YAML dependency: this repo ships four runtime deps and a parser for one
// list is not the fifth.
function workflowTriggerPaths(workflow) {
  const lines = workflow.split('\n');
  const start = lines.findIndex((l) => /^\s{4}paths:\s*$/.test(l));
  assert.notEqual(start, -1, 'publish.yml has no `paths:` block under on.push');
  const out = [];
  for (const line of lines.slice(start + 1)) {
    const m = line.match(/^\s+-\s+'([^']+)'\s*$/);
    if (m) {
      out.push(m[1]);
      continue;
    }
    if (line.trim() === '' || line.trim().startsWith('#')) continue;
    break; // dedented out of the list
  }
  return out;
}

// `src/**` covers `src`; `package.json` covers itself.
const covers = (entry, source) =>
  entry === source || entry.replace(/\/\*+$/, '') === source.replace(/\/+$/, '');

test('every path the Dockerfile COPYs triggers a publish', () => {
  const sources = dockerfileCopySources(read('Dockerfile'));
  const paths = workflowTriggerPaths(read('.github/workflows/publish.yml'));

  assert.ok(sources.length > 0, 'parsed no COPY sources — the parser is broken, not the Dockerfile');

  for (const source of sources) {
    assert.ok(
      paths.some((p) => covers(p, source)),
      `Dockerfile COPYs "${source}" but .github/workflows/publish.yml does not ` +
        `trigger on it (paths: ${JSON.stringify(paths)}). A push changing only ` +
        `that path would publish NOTHING and look like a clean merge.`,
    );
  }
});

test('the Dockerfile itself triggers a publish', () => {
  // Not a COPY source, but it decides the image's base and layers — editing it
  // changes the artifact without touching a single copied file.
  const paths = workflowTriggerPaths(read('.github/workflows/publish.yml'));
  assert.ok(paths.includes('Dockerfile'));
});

// Guards the parser. Both functions above silently returning [] would make the
// first test vacuously pass — the classic instrument-that-cannot-fail.
test('the parsers actually parse', () => {
  assert.deepEqual(
    dockerfileCopySources('COPY package.json package-lock.json* ./\nCOPY src ./src\n'),
    ['package.json', 'package-lock.json', 'src'],
  );
  assert.deepEqual(
    workflowTriggerPaths("on:\n  push:\n    paths:\n      - 'src/**'\n      - 'Dockerfile'\n\njobs:\n"),
    ['src/**', 'Dockerfile'],
  );
});
