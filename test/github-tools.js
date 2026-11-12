/** Integration tests for GitHub worktree tools, logical locks, and Claude security gates. */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { loadBackends } from "../src/backends.js";
import { assertCwdAllowed, realPathResolve } from "../src/security.js";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "cli.js");
const GIT = process.env.GIT_BIN || (process.platform === "win32" && fs.existsSync("D:\\Git\\cmd\\git.exe") ? "D:\\Git\\cmd\\git.exe" : "git");

const ROOT = path.join(os.tmpdir(), `antigravity-mcp-github-test-${process.pid}`);
const MCP_HOME = path.join(ROOT, "mcp-home");
const HOST_HOME = path.join(ROOT, "host-home");
const ORIGIN_BARE = path.join(ROOT, "origin.git");
const REPO_DIR = path.join(ROOT, "repos", "demo-proj");
const WORKTREE_ROOT = path.join(ROOT, "agent-worktrees", "demo-proj");
const PROJECTS_FILE = path.join(MCP_HOME, "projects.json");

let failures = 0;
const check = (name, cond, extra = "") => {
  console.log(`  ${cond ? "+" : "x"} ${name}${extra ? ` — ${extra}` : ""}`);
  if (!cond) failures++;
};

function git(cwd, args) {
  const res = spawnSync(GIT, args, { cwd, encoding: "utf8", windowsHide: true });
  if (res.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed in ${cwd}: ${(res.stderr || res.stdout || "").trim()}`);
  }
  return (res.stdout || "").trim();
}

function setupFixture() {
  fs.rmSync(ROOT, { recursive: true, force: true });
  fs.mkdirSync(MCP_HOME, { recursive: true });
  fs.mkdirSync(HOST_HOME, { recursive: true });
  fs.mkdirSync(path.dirname(REPO_DIR), { recursive: true });
  fs.mkdirSync(WORKTREE_ROOT, { recursive: true });

  fs.mkdirSync(ORIGIN_BARE, { recursive: true });
  git(ORIGIN_BARE, ["init", "--bare", "--initial-branch=main"]);

  git(ROOT, ["clone", ORIGIN_BARE, REPO_DIR]);
  git(REPO_DIR, ["config", "user.name", "Test Runner"]);
  git(REPO_DIR, ["config", "user.email", "test@example.com"]);
  git(REPO_DIR, ["checkout", "-b", "main"]);

  fs.mkdirSync(path.join(REPO_DIR, "src"), { recursive: true });
  fs.writeFileSync(path.join(REPO_DIR, "src", "app.js"), "export const add = (a, b) => a + b;\n");
  fs.writeFileSync(path.join(REPO_DIR, "src", "other.js"), "export const sub = (a, b) => a - b;\n");
  fs.writeFileSync(
    path.join(REPO_DIR, "test.js"),
    "import assert from 'node:assert/strict';\nimport { add } from './src/app.js';\nassert.equal(add(2, 3), 5);\nconsole.log('ok');\n"
  );
  fs.writeFileSync(
    path.join(REPO_DIR, "package.json"),
    JSON.stringify({ name: "demo-proj", type: "module", scripts: { test: "node test.js" } }, null, 2) + "\n"
  );
  git(REPO_DIR, ["add", "."]);
  git(REPO_DIR, ["commit", "-m", "initial commit"]);
  git(REPO_DIR, ["push", "-u", "origin", "main"]);

  fs.writeFileSync(
    PROJECTS_FILE,
    JSON.stringify(
      {
        projects: {
          "demo-proj": {
            repository: "rootdgy/demo-proj",
            defaultBranch: "main",
            vpsPath: REPO_DIR,
            worktreeRoot: WORKTREE_ROOT,
            testCommand: "npm test",
            allowed: true,
          },
        },
      },
      null,
      2
    )
  );
}

async function connect(agent) {
  const client = new Client({ name: `gh-test-${agent}`, version: "0" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [CLI, "--agent", agent],
      env: {
        ...process.env,
        ANTIGRAVITY_MCP_HOME: MCP_HOME,
        ANTIGRAVITY_MCP_HOST_HOME: HOST_HOME,
        ANTIGRAVITY_PROJECTS_FILE: PROJECTS_FILE,
        CLAUDE_BIN: process.execPath,
        GIT_BIN: GIT,
      },
    })
  );
  return client;
}

const call = async (c, name, args = {}) =>
  JSON.parse((await c.callTool({ name, arguments: args })).content[0].text);

console.log("\nantigravity-mcp-server github & security integration test\n");
setupFixture();

const alice = await connect("antigravity-win11");
const bob = await connect("worker-2");

try {
  // 1. Tool discovery
  const toolNames = new Set((await alice.listTools()).tools.map((t) => t.name));
  const EXPECTED_GITHUB_TOOLS = [
    "project_list",
    "project_status",
    "github_prepare_task",
    "github_task_diff",
    "github_validate_task",
    "github_publish_task",
    "github_create_pr",
    "github_cleanup_task",
  ];
  check(
    "all 8 GitHub/project tools registered",
    EXPECTED_GITHUB_TOOLS.every((t) => toolNames.has(t)),
    EXPECTED_GITHUB_TOOLS.filter((t) => !toolNames.has(t)).join(",") || "all 8"
  );
  check("claude_delegate registered when CLAUDE_BIN available", toolNames.has("claude_delegate"));

  // 2. Project listing & status
  const listRes = await call(alice, "project_list");
  check(
    "project_list returns demo-proj",
    listRes.count === 1 && listRes.projects[0].project_id === "demo-proj" && listRes.projects[0].clean === true
  );

  const statusRes = await call(alice, "project_status", { project_id: "demo-proj", fetch: true });
  check(
    "project_status matches main and remote HEAD",
    statusRes.branch === "main" && statusRes.local_head === statusRes.remote_head && statusRes.clean === true
  );

  // 3. Path traversal & dirty-main protections on github_prepare_task
  const badId = await call(alice, "github_prepare_task", { project_id: "demo-proj", task_id: "../escape" });
  check("github_prepare_task rejects invalid task_id traversal", Boolean(badId.error));

  fs.writeFileSync(path.join(REPO_DIR, "dirty.tmp"), "dirty\n");
  const dirtyPrep = await call(alice, "github_prepare_task", { project_id: "demo-proj", task_id: "task-001" });
  check("github_prepare_task blocks when main repo is dirty", /uncommitted changes/i.test(dirtyPrep.error || ""));
  fs.unlinkSync(path.join(REPO_DIR, "dirty.tmp"));

  const prep1 = await call(alice, "github_prepare_task", { project_id: "demo-proj", task_id: "task-001" });
  check(
    "github_prepare_task creates isolated worktree and claude/task-001 branch",
    !prep1.error &&
      prep1.branch === "claude/task-001" &&
      fs.existsSync(prep1.cwd) &&
      realPathResolve(prep1.cwd).startsWith(realPathResolve(WORKTREE_ROOT))
  );

  // 4. Cross-worktree logical file lock detection
  const prep2 = await call(bob, "github_prepare_task", { project_id: "demo-proj", task_id: "task-002" });
  check("second worktree task-002 prepared", !prep2.error && fs.existsSync(prep2.cwd));

  const wt1App = path.join(prep1.cwd, "src", "app.js");
  const wt2App = path.join(prep2.cwd, "src", "app.js");
  const wt2Other = path.join(prep2.cwd, "src", "other.js");

  const lock1 = await call(alice, "claim_paths", { paths: [wt1App], task_id: "task-001", note: "editing add()" });
  check("alice claims wt1 src/app.js", lock1.granted.length === 1 && lock1.conflicts.length === 0);

  const chk = await call(bob, "check_paths", { paths: [wt2App, wt2Other] });
  check(
    "check_paths detects cross-worktree logical lock on src/app.js",
    chk.paths[0].free === false &&
      chk.paths[0].held_by === "antigravity-win11" &&
      chk.paths[0].logical_key === "logical://demo-proj/src/app.js" &&
      chk.paths[1].free === true
  );

  const lock2 = await call(bob, "claim_paths", { paths: [wt2App, wt2Other], task_id: "task-002" });
  check(
    "claim_paths blocks conflicting file across worktrees and grants non-conflicting file",
    lock2.conflicts.length === 1 && lock2.granted.length === 1
  );

  // Clean up test locks before proceeding
  await call(alice, "release_paths", { all_mine: true });
  await call(bob, "release_paths", { all_mine: true });

  // 5. Modify worktree, inspect diff, test validation & secret blocking
  fs.writeFileSync(path.join(prep1.cwd, "src", "app.js"), "export const add = (a, b) => Number(a) + Number(b);\n");

  const diffRes = await call(alice, "github_task_diff", { project_id: "demo-proj", task_id: "task-001" });
  check(
    "github_task_diff shows modified src/app.js",
    !diffRes.error && /Number\(a\)/.test(diffRes.diff || "") && diffRes.branch === "claude/task-001"
  );

  const validPass = await call(alice, "github_validate_task", { project_id: "demo-proj", task_id: "task-001", run_tests: true });
  check(
    "github_validate_task passes clean code + npm test",
    validPass.valid === true && validPass.test_status === "passed",
    JSON.stringify(validPass.errors || [])
  );

  // Introduce forbidden .env file & secret token in diff
  fs.writeFileSync(path.join(prep1.cwd, ".env"), "SECRET=123\n");
  fs.writeFileSync(path.join(prep1.cwd, "src", "other.js"), "export const leak = 'ghp_1234567890abcdef1234567890abcdef123456';\n");

  const validFail = await call(alice, "github_validate_task", { project_id: "demo-proj", task_id: "task-001", run_tests: false });
  check(
    "github_validate_task blocks .env and secret patterns",
    validFail.valid === false && validFail.secret_findings.length >= 2
  );

  const envPublish = await call(alice, "github_publish_task", {
    project_id: "demo-proj",
    task_id: "task-001",
    commit_message: "should fail",
    confirm_publish: true,
    run_tests: false,
  });
  check("github_publish_task refuses forbidden .env file", /Refusing to stage '.env'/i.test(envPublish.error || ""));

  // Restore clean files
  fs.unlinkSync(path.join(prep1.cwd, ".env"));
  git(prep1.cwd, ["checkout", "--", "src/other.js"]);

  // 6. Publish approval gate, push & remote SHA verification, PR fallback
  const noApprovePub = await call(alice, "github_publish_task", {
    project_id: "demo-proj",
    task_id: "task-001",
    commit_message: "feat: coerce numbers in add",
    confirm_publish: false,
  });
  check("github_publish_task requires confirm_publish=true", noApprovePub.status === "waiting_for_approval");

  const pubRes = await call(alice, "github_publish_task", {
    project_id: "demo-proj",
    task_id: "task-001",
    commit_message: "feat: coerce numbers in add",
    confirm_publish: true,
    run_tests: true,
  });
  const originBranchSha = git(ORIGIN_BARE, ["rev-parse", "refs/heads/claude/task-001"]);
  check(
    "github_publish_task commits and pushes verified SHA to bare origin",
    pubRes.status === "pushed" && pubRes.commit_sha === originBranchSha && pubRes.test_status === "passed",
    JSON.stringify(pubRes)
  );

  const prRes = await call(alice, "github_create_pr", {
    project_id: "demo-proj",
    task_id: "task-001",
    title: "Coerce numbers in add()",
  });
  check(
    "github_create_pr returns compare URL or PR info for pushed branch",
    Boolean(prRes.compare_url || prRes.pr_url) && prRes.commit_sha === originBranchSha
  );

  // 7. Safe worktree cleanup checks
  fs.writeFileSync(path.join(prep2.cwd, "uncommitted.txt"), "wip\n");
  const dirtyClean = await call(bob, "github_cleanup_task", {
    project_id: "demo-proj",
    task_id: "task-002",
    confirm_cleanup: true,
  });
  check("github_cleanup_task refuses dirty worktree", /uncommitted changes/i.test(dirtyClean.error || ""));
  fs.unlinkSync(path.join(prep2.cwd, "uncommitted.txt"));

  const noConfirmClean = await call(alice, "github_cleanup_task", {
    project_id: "demo-proj",
    task_id: "task-001",
    confirm_cleanup: false,
  });
  check("github_cleanup_task requires confirm_cleanup=true", /confirm_cleanup=true/i.test(noConfirmClean.error || ""));

  const okClean1 = await call(alice, "github_cleanup_task", {
    project_id: "demo-proj",
    task_id: "task-001",
    confirm_cleanup: true,
  });
  await call(bob, "github_cleanup_task", { project_id: "demo-proj", task_id: "task-002", confirm_cleanup: true });
  check(
    "github_cleanup_task removes pushed worktree when confirmed",
    okClean1.cleaned === true && !fs.existsSync(prep1.cwd),
    JSON.stringify(okClean1)
  );

  // 8. Claude security & approval gates (zero cost, pre-spawn rejections + arg building)
  const blockedCwd = await call(alice, "claude_delegate", {
    title: "outside whitelist",
    prompt: "inspect",
    cwd: os.tmpdir(),
  });
  check("claude_delegate blocks cwd outside project whitelist", /Access denied/i.test(blockedCwd.error || ""));

  const blockedExec = await call(alice, "claude_delegate", {
    title: "unapproved execute",
    prompt: "modify file",
    cwd: REPO_DIR,
    mode: "execute",
  });
  check(
    "claude_delegate blocks mode=execute without approval_confirmed=true",
    blockedExec.status === "waiting_for_approval" && /approval_confirmed=true/i.test(blockedExec.error || "")
  );

  // Unit checks for Claude CLI flags & assertCwdAllowed
  const claudeSpec = loadBackends().find((b) => b.id === "claude");
  const planArgs = claudeSpec.build({ prompt: "analyze", cwd: REPO_DIR });
  check(
    "claude backend defaults to --permission-mode plan, Read/Grep/Glob, and never --dangerously-skip-permissions",
    planArgs.includes("--permission-mode") &&
      planArgs[planArgs.indexOf("--permission-mode") + 1] === "plan" &&
      planArgs.includes("--tools") &&
      planArgs[planArgs.indexOf("--tools") + 1] === "Read,Grep,Glob" &&
      planArgs.includes("--disallowedTools") &&
      !planArgs.includes("--dangerously-skip-permissions")
  );

  const execArgs = claudeSpec.build({ prompt: "edit", cwd: REPO_DIR, mode: "execute", autoApprove: true });
  check(
    "claude backend execute mode uses acceptEdits, allowedTools, and ignores autoApprove by default",
    execArgs[execArgs.indexOf("--permission-mode") + 1] === "acceptEdits" &&
      execArgs.includes("--allowedTools") &&
      !execArgs.includes("--dangerously-skip-permissions")
  );

  let bypassThrew = false;
  try {
    claudeSpec.build({ prompt: "bad", cwd: REPO_DIR, permissionMode: "bypassPermissions" });
  } catch {
    bypassThrew = true;
  }
  check("claude backend rejects bypassPermissions", bypassThrew);

  process.env.ANTIGRAVITY_PROJECTS_FILE = PROJECTS_FILE;
  let outsideThrew = false;
  try {
    assertCwdAllowed(path.join(os.homedir(), ".ssh"));
  } catch {
    outsideThrew = true;
  }
  check("assertCwdAllowed blocks ~/.ssh", outsideThrew);
} finally {
  await alice.close().catch(() => {});
  await bob.close().catch(() => {});
  fs.rmSync(ROOT, { recursive: true, force: true });
}

console.log(`\n${failures ? `${failures} FAILED` : "ALL PASSED"}\n`);
process.exit(failures ? 1 : 0);
