/**
 * Security, path-whitelist, logical worktree locking, and diff secret-scanning helpers.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { stateDir, norm } from "./store.js";

const FORBIDDEN_SYSTEM_ROOTS = process.platform === "win32"
  ? []
  : ["/etc", "/root", "/var", "/usr", "/bin", "/sbin", "/boot", "/proc", "/sys", "/dev"];

const FORBIDDEN_FILE_PATTERNS = [
  /^\.env$/i,
  /^\.env\.(?!example$)/i,
  /\.pem$/i,
  /\.key$/i,
  /^id_rsa(?:\..*)?$/i,
  /^id_ed25519(?:\..*)?$/i,
  /^credentials\.json$/i,
  /^service-account\.json$/i,
];

const FORBIDDEN_DIR_SEGMENTS = new Set([
  "node_modules",
  ".venv",
  "__pycache__",
  ".antigravity-mcp",
  ".claude",
]);

const SECRET_CONTENT_PATTERNS = [
  { name: "private-key", regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
  { name: "github-pat", regex: /\bghp_[A-Za-z0-9]{30,}\b/ },
  { name: "github-fine-pat", regex: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/ },
  { name: "anthropic-key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: "aws-access-key", regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "slack-token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "google-api-key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
];

export function projectsFilePath() {
  return process.env.ANTIGRAVITY_PROJECTS_FILE
    ? path.resolve(process.env.ANTIGRAVITY_PROJECTS_FILE)
    : path.join(stateDir(), "projects.json");
}

export function loadProjectsRegistry() {
  const file = projectsFilePath();
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return { projects: {}, exists: false, file };
    throw err;
  }
  const parsed = JSON.parse(raw);
  return { projects: parsed?.projects || {}, exists: true, file };
}

export function assertValidId(value, label = "id") {
  if (typeof value !== "string" || !/^[a-zA-Z0-9._-]+$/.test(value) || value === "." || value === ".." || value.includes("..")) {
    throw new Error(`Invalid ${label}: ${String(value)}`);
  }
  return value;
}

/**
 * Resolve symlinks on the deepest existing ancestor so non-existent leaf paths
 * (such as a worktree directory about to be created) still defeat symlink escapes.
 */
export function realPathResolve(targetPath) {
  const abs = path.resolve(targetPath);
  const parts = [];
  let cur = abs;
  while (!fs.existsSync(cur)) {
    const parent = path.dirname(cur);
    if (parent === cur) break;
    parts.unshift(path.basename(cur));
    cur = parent;
  }
  let baseReal;
  try {
    baseReal = fs.realpathSync(cur);
  } catch {
    baseReal = cur;
  }
  const resolved = parts.length ? path.join(baseReal, ...parts) : baseReal;
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

export function isPathInside(candidate, root) {
  const c = realPathResolve(candidate);
  const r = realPathResolve(root);
  return c === r || c.startsWith(r + path.sep);
}

export function allowedRootsList() {
  const roots = [];
  if (process.env.ANTIGRAVITY_ALLOWED_ROOTS) {
    for (const entry of process.env.ANTIGRAVITY_ALLOWED_ROOTS.split(path.delimiter).filter(Boolean)) {
      roots.push(entry);
    }
  }
  const { projects } = loadProjectsRegistry();
  for (const p of Object.values(projects)) {
    if (!p?.allowed) continue;
    if (p.vpsPath) roots.push(p.vpsPath);
    if (p.worktreeRoot) roots.push(p.worktreeRoot);
  }
  return roots;
}

/**
 * Enforce directory whitelist and block sensitive OS/SSH paths.
 * When no projects are registered and ANTIGRAVITY_ALLOWED_ROOTS is unset,
 * only forbids sensitive OS/SSH directories so sandboxed unit tests still run.
 */
export function assertCwdAllowed(cwd, { requireWorktree = false } = {}) {
  const resolved = realPathResolve(cwd);

  for (const sysRoot of FORBIDDEN_SYSTEM_ROOTS) {
    const sysNorm = process.platform === "win32" ? sysRoot.toLowerCase() : sysRoot;
    if (resolved === sysNorm || resolved.startsWith(sysNorm + path.sep)) {
      throw new Error(`Access denied: ${cwd} is inside forbidden system directory ${sysRoot}`);
    }
  }

  const sshDir = path.join(os.homedir(), ".ssh");
  if (isPathInside(resolved, sshDir)) {
    throw new Error(`Access denied: ${cwd} is inside ~/.ssh`);
  }

  const { projects } = loadProjectsRegistry();
  const allowedProjects = Object.values(projects).filter((p) => p?.allowed);
  const envRoots = process.env.ANTIGRAVITY_ALLOWED_ROOTS
    ? process.env.ANTIGRAVITY_ALLOWED_ROOTS.split(path.delimiter).filter(Boolean)
    : [];

  if (allowedProjects.length === 0 && envRoots.length === 0) {
    return resolved;
  }

  const candidateRoots = requireWorktree
    ? [...allowedProjects.map((p) => p.worktreeRoot).filter(Boolean), ...envRoots]
    : [...allowedProjects.flatMap((p) => [p.worktreeRoot, p.vpsPath]).filter(Boolean), ...envRoots];

  if (!candidateRoots.some((root) => isPathInside(resolved, root))) {
    throw new Error(
      `Access denied: ${cwd} is outside allowed ${requireWorktree ? "worktree" : "project"} roots`
    );
  }
  return resolved;
}

/**
 * Map a filesystem path inside a repo or one of its worktrees to a canonical
 * logical lock key (`logical://<project_id>/<relative_posix_path>`), so two
 * tasks working in separate Git Worktrees detect conflicts on the same file.
 */
export function resolveLockKey(rawPath) {
  const absPath = norm(rawPath);
  const { projects } = loadProjectsRegistry();
  const realTarget = realPathResolve(absPath);

  for (const [projectId, p] of Object.entries(projects)) {
    if (!p?.allowed) continue;

    if (p.vpsPath) {
      const repoReal = realPathResolve(p.vpsPath);
      if (realTarget === repoReal || realTarget.startsWith(repoReal + path.sep)) {
        const rel = path.relative(repoReal, realTarget).split(path.sep).join("/") || ".";
        return { absPath, logicalKey: `logical://${projectId}/${rel}`, projectId, relPath: rel };
      }
    }

    if (p.worktreeRoot) {
      const wtRootReal = realPathResolve(p.worktreeRoot);
      if (realTarget.startsWith(wtRootReal + path.sep)) {
        const afterRoot = path.relative(wtRootReal, realTarget);
        const parts = afterRoot.split(path.sep).filter(Boolean);
        if (parts.length >= 1) {
          const rel = parts.slice(1).join("/") || ".";
          return { absPath, logicalKey: `logical://${projectId}/${rel}`, projectId, relPath: rel };
        }
      }
    }
  }

  return { absPath, logicalKey: null, projectId: null, relPath: null };
}

export function logicalKeysOverlap(a, b) {
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.endsWith("/.") && b.startsWith(a.slice(0, -1))) return true;
  if (b.endsWith("/.") && a.startsWith(b.slice(0, -1))) return true;
  return a.startsWith(b + "/") || b.startsWith(a + "/");
}

export function isForbiddenRepoFile(relFilePath) {
  const posix = String(relFilePath).replace(/\\/g, "/");
  const segments = posix.split("/").filter(Boolean);
  for (const seg of segments) {
    if (FORBIDDEN_DIR_SEGMENTS.has(seg)) return `forbidden directory segment '${seg}'`;
  }
  const base = segments[segments.length - 1] || "";
  for (const re of FORBIDDEN_FILE_PATTERNS) {
    if (re.test(base)) return `forbidden sensitive filename '${base}'`;
  }
  return null;
}

export function scanDiffForSecrets(diffText, changedFiles = []) {
  const findings = [];
  for (const f of changedFiles) {
    const reason = isForbiddenRepoFile(f);
    if (reason) findings.push({ file: f, kind: "forbidden_file", detail: reason });
  }
  let currentFile = null;
  for (const line of String(diffText || "").split(/\r?\n/)) {
    if (line.startsWith("+++ b/")) {
      currentFile = line.slice(6);
      continue;
    }
    if (!line.startsWith("+") || line.startsWith("+++")) continue;
    for (const pat of SECRET_CONTENT_PATTERNS) {
      if (pat.regex.test(line)) {
        findings.push({
          file: currentFile || "(diff)",
          kind: "secret_pattern",
          detail: `matched ${pat.name}`,
        });
      }
    }
  }
  return findings;
}
