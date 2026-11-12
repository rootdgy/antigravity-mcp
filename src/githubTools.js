/**
 * GitHub workspace & Git Worktree MCP tool extensions.
 *
 * Uses spawnSync with explicit argument arrays (never shell string interpolation)
 * and enforces project whitelist + path traversal checks via security.js.
 */

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { z } from "zod";
import { mutate, logEvent } from "./store.js";
import {
  assertValidId,
  assertCwdAllowed,
  isPathInside,
  isForbiddenRepoFile,
  loadProjectsRegistry,
  realPathResolve,
  scanDiffForSecrets,
} from "./security.js";

const ok = (obj) => ({
  content: [{ type: "text", text: JSON.stringify(obj) }],
});

function runGit(cwd, args, { allowFail = false } = {}) {
  const res = spawnSync(process.env.GIT_BIN || "git", ["-C", cwd, ...args], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 60_000,
  });
  if (res.error) throw res.error;
  if (res.status !== 0 && !allowFail) {
    const msg = (res.stderr || res.stdout || `git exited with ${res.status}`).trim();
    throw new Error(`git ${args[0]} failed: ${msg}`);
  }
  return {
    status: res.status ?? 0,
    stdout: (res.stdout || "").trimEnd(),
    stderr: (res.stderr || "").trimEnd(),
  };
}

function getAllowedProject(projectId) {
  assertValidId(projectId, "project_id");
  const { projects, file } = loadProjectsRegistry();
  const project = projects[projectId];
  if (!project || !project.allowed) {
    throw new Error(`Project '${projectId}' is not registered or not allowed in ${file}`);
  }
  if (!project.vpsPath || !project.worktreeRoot) {
    throw new Error(`Project '${projectId}' is missing vpsPath or worktreeRoot`);
  }
  assertCwdAllowed(project.vpsPath);
  return {
    ...project,
    projectId,
    defaultBranch: project.defaultBranch || "main",
  };
}

function resolveTaskWorktree(project, taskId) {
  assertValidId(taskId, "task_id");
  const wtDir = path.join(project.worktreeRoot, taskId);
  if (!isPathInside(wtDir, project.worktreeRoot)) {
    throw new Error(`Worktree path escaped worktreeRoot: ${wtDir}`);
  }
  assertCwdAllowed(wtDir, { requireWorktree: true });
  return wtDir;
}

function parseTestCommand(cmd) {
  if (!cmd || typeof cmd !== "string") return null;
  const parts = cmd.trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return null;
  const allowedBins = new Set(["npm", "pnpm", "yarn", "node", "npx", "pytest", "python", "python3"]);
  if (!allowedBins.has(parts[0])) {
    throw new Error(`Refusing unwhitelisted test runner '${parts[0]}'`);
  }
  if (/[;&|`$<>]/.test(cmd)) {
    throw new Error("Refusing testCommand containing shell metacharacters");
  }
  return { bin: parts[0], args: parts.slice(1) };
}

function runConfiguredTests(project, wtDir) {
  if (!project.testCommand) return { testStatus: "skipped", testOutput: "", exitCode: 0 };
  const parsed = parseTestCommand(project.testCommand);
  if (!parsed) return { testStatus: "skipped", testOutput: "", exitCode: 0 };
  const useCmdShim = process.platform === "win32" && ["npm", "pnpm", "yarn", "npx"].includes(parsed.bin);
  const bin = useCmdShim ? process.env.ComSpec || "cmd.exe" : parsed.bin;
  const args = useCmdShim ? ["/d", "/c", parsed.bin, ...parsed.args] : parsed.args;
  const tRes = spawnSync(bin, args, {
    cwd: wtDir,
    encoding: "utf8",
    windowsHide: true,
    timeout: 180_000,
  });
  const testStatus = tRes.status === 0 ? "passed" : "failed";
  const testOutput = ((tRes.stdout || "") + "\n" + (tRes.stderr || "")).trim().slice(-2000);
  return { testStatus, testOutput, exitCode: tRes.status };
}

function githubHttpsUrl(repo) {
  if (!repo) return null;
  if (repo.startsWith("https://")) return repo.replace(/\.git$/, "");
  return `https://github.com/${repo}`;
}

export function registerGithubTools(server, { agentName = () => "agent" } = {}) {
  server.registerTool(
    "project_list",
    {
      title: "List whitelisted GitHub projects",
      description:
        "List authorized GitHub projects registered on this VPS, including repository, " +
        "default branch, local VPS path, and current git sync state.",
      inputSchema: {},
    },
    async () => {
      const { projects, exists, file } = loadProjectsRegistry();
      const items = [];
      for (const [id, p] of Object.entries(projects)) {
        if (!p?.allowed) continue;
        const repoExists = fs.existsSync(path.join(p.vpsPath, ".git"));
        let branch = null;
        let headSha = null;
        let clean = null;
        if (repoExists) {
          branch = runGit(p.vpsPath, ["rev-parse", "--abbrev-ref", "HEAD"], { allowFail: true }).stdout || null;
          headSha = runGit(p.vpsPath, ["rev-parse", "HEAD"], { allowFail: true }).stdout || null;
          const st = runGit(p.vpsPath, ["status", "--porcelain"], { allowFail: true }).stdout;
          clean = st === "";
        }
        items.push({
          project_id: id,
          repository: p.repository,
          default_branch: p.defaultBranch || "main",
          vps_path: p.vpsPath,
          worktree_root: p.worktreeRoot,
          repo_present: repoExists,
          branch,
          head_sha: headSha,
          clean,
        });
      }
      return ok({ registry_exists: exists, registry_file: file, count: items.length, projects: items });
    }
  );

  server.registerTool(
    "project_status",
    {
      title: "Inspect a GitHub project's git status",
      description:
        "Inspect a whitelisted project's GitHub remote, current branch, local HEAD, remote HEAD, " +
        "uncommitted files, active worktrees, and merge conflicts.",
      inputSchema: {
        project_id: z.string(),
        fetch: z.boolean().optional().describe("Fetch origin before reading remote HEAD (default true)"),
      },
    },
    async ({ project_id, fetch = true }) => {
      try {
        const project = getAllowedProject(project_id);
        if (!fs.existsSync(path.join(project.vpsPath, ".git"))) {
          return ok({ error: `Repository not cloned at ${project.vpsPath}` });
        }
        if (fetch) {
          runGit(project.vpsPath, ["fetch", "origin", "--prune"]);
        }
        const remote = runGit(project.vpsPath, ["remote", "get-url", "origin"], { allowFail: true }).stdout;
        const branch = runGit(project.vpsPath, ["rev-parse", "--abbrev-ref", "HEAD"]).stdout;
        const localHead = runGit(project.vpsPath, ["rev-parse", "HEAD"]).stdout;
        const remoteHead = runGit(
          project.vpsPath,
          ["rev-parse", "--verify", `origin/${project.defaultBranch}`],
          { allowFail: true }
        ).stdout || null;
        const statusLines = runGit(project.vpsPath, ["status", "--porcelain"]).stdout
          .split(/\r?\n/)
          .filter(Boolean);
        const conflicts = statusLines.filter((l) => /^(UU|AA|DD|AU|UA|DU|UD)\s/.test(l));
        const wtRaw = runGit(project.vpsPath, ["worktree", "list", "--porcelain"]).stdout;
        const worktrees = wtRaw
          .split(/\r?\n\r?\n/)
          .filter(Boolean)
          .map((blk) => {
            const wt = blk.match(/^worktree (.+)$/m)?.[1] || "";
            const br = blk.match(/^branch refs\/heads\/(.+)$/m)?.[1] || "";
            return { path: wt, branch: br };
          });
        return ok({
          project_id,
          repository: project.repository,
          vps_path: project.vpsPath,
          remote,
          default_branch: project.defaultBranch,
          branch,
          local_head: localHead,
          remote_head: remoteHead,
          clean: statusLines.length === 0,
          uncommitted_files: statusLines,
          conflicts,
          worktrees,
        });
      } catch (err) {
        return ok({ error: err.message });
      }
    }
  );

  server.registerTool(
    "github_prepare_task",
    {
      title: "Prepare an isolated Git Worktree for a Claude task",
      description:
        "Fetch origin, verify the main repository is clean, create branch claude/<task_id> and an " +
        "isolated Git Worktree directory, and return the real VPS cwd for Claude Code.",
      inputSchema: {
        project_id: z.string(),
        task_id: z.string().describe("Unique task identifier (e.g. task-20261112-001)"),
        base_branch: z.string().optional().describe("Base branch on origin (defaults to project defaultBranch)"),
      },
    },
    async ({ project_id, task_id, base_branch }) => {
      try {
        const project = getAllowedProject(project_id);
        const baseBranch = base_branch || project.defaultBranch;
        assertValidId(baseBranch, "base_branch");
        if (!fs.existsSync(path.join(project.vpsPath, ".git"))) {
          return ok({ error: `Repository not cloned at ${project.vpsPath}` });
        }

        const dirtyMain = runGit(project.vpsPath, ["status", "--porcelain"]).stdout;
        if (dirtyMain) {
          return ok({ error: `Main repository ${project.vpsPath} has uncommitted changes; refusing to prepare worktree.` });
        }

        runGit(project.vpsPath, ["fetch", "origin", "--prune"]);
        const baseShaRes = runGit(project.vpsPath, ["rev-parse", "--verify", `refs/remotes/origin/${baseBranch}`], { allowFail: true });
        if (baseShaRes.status !== 0) {
          return ok({ error: `Remote base branch origin/${baseBranch} not found` });
        }
        const baseSha = baseShaRes.stdout;

        const taskBranch = `claude/${task_id}`;
        const wtDir = resolveTaskWorktree(project, task_id);
        fs.mkdirSync(path.dirname(wtDir), { recursive: true });

        if (fs.existsSync(wtDir)) {
          const curBranch = runGit(wtDir, ["rev-parse", "--abbrev-ref", "HEAD"], { allowFail: true }).stdout;
          if (curBranch !== taskBranch) {
            return ok({ error: `Worktree directory ${wtDir} already exists on branch '${curBranch}', expected '${taskBranch}'` });
          }
        } else {
          const hasBranch = runGit(project.vpsPath, ["show-ref", "--verify", `refs/heads/${taskBranch}`], { allowFail: true }).status === 0;
          if (hasBranch) {
            runGit(project.vpsPath, ["worktree", "add", wtDir, taskBranch]);
          } else {
            runGit(project.vpsPath, ["worktree", "add", "-b", taskBranch, wtDir, `origin/${baseBranch}`]);
          }
        }

        const realCwd = fs.realpathSync(wtDir);
        await mutate((b) => logEvent(b, agentName(), "github.prepare_task", `${project_id}:${taskBranch} @ ${baseSha.slice(0, 8)}`));
        return ok({
          task_id,
          project_id,
          repository: project.repository,
          branch: taskBranch,
          base_branch: baseBranch,
          base_sha: baseSha,
          cwd: realCwd,
        });
      } catch (err) {
        return ok({ error: err.message });
      }
    }
  );

  server.registerTool(
    "github_task_diff",
    {
      title: "Inspect Git Diff and file changes in a task worktree",
      description:
        "Return current branch, HEAD commit SHA, modified/added/deleted/untracked files, diff stat, " +
        "and unified diff for a prepared Claude task worktree.",
      inputSchema: {
        project_id: z.string(),
        task_id: z.string(),
        base_branch: z.string().optional(),
        max_diff_chars: z.number().int().optional(),
      },
    },
    async ({ project_id, task_id, base_branch, max_diff_chars = 16000 }) => {
      try {
        const project = getAllowedProject(project_id);
        const wtDir = resolveTaskWorktree(project, task_id);
        if (!fs.existsSync(wtDir)) {
          return ok({ error: `Task worktree not found: ${wtDir}` });
        }
        const baseBranch = base_branch || project.defaultBranch;
        assertValidId(baseBranch, "base_branch");

        const branch = runGit(wtDir, ["rev-parse", "--abbrev-ref", "HEAD"]).stdout;
        const headSha = runGit(wtDir, ["rev-parse", "HEAD"]).stdout;
        const statusLines = runGit(wtDir, ["status", "--porcelain"]).stdout.split(/\r?\n/).filter(Boolean);
        const committedFiles = runGit(
          wtDir,
          ["diff", "--name-status", `origin/${baseBranch}..HEAD`],
          { allowFail: true }
        ).stdout.split(/\r?\n/).filter(Boolean);
        const workingStat = runGit(wtDir, ["diff", "--stat", `origin/${baseBranch}`], { allowFail: true }).stdout;
        const untracked = runGit(wtDir, ["ls-files", "--others", "--exclude-standard"]).stdout.split(/\r?\n/).filter(Boolean);
        const rawDiff = runGit(wtDir, ["diff", `origin/${baseBranch}`], { allowFail: true }).stdout;
        const truncated = rawDiff.length > max_diff_chars;
        const diff = truncated ? rawDiff.slice(0, max_diff_chars) + `\n...[truncated ${rawDiff.length - max_diff_chars} chars]...` : rawDiff;

        return ok({
          task_id,
          project_id,
          cwd: wtDir,
          branch,
          head_sha: headSha,
          status_lines: statusLines,
          committed_changes: committedFiles,
          untracked_files: untracked,
          stat: workingStat,
          diff,
          diff_truncated: truncated,
        });
      } catch (err) {
        return ok({ error: err.message });
      }
    }
  );

  server.registerTool(
    "github_validate_task",
    {
      title: "Validate a task worktree before publishing",
      description:
        "Check git status, branch name, forbidden/secret files, accidental deletions, lockfile changes, " +
        "scan Git Diff for secrets, and optionally run the project's testCommand.",
      inputSchema: {
        project_id: z.string(),
        task_id: z.string(),
        base_branch: z.string().optional(),
        run_tests: z.boolean().optional().describe("Run project testCommand (default true if configured)"),
      },
    },
    async ({ project_id, task_id, base_branch, run_tests = true }) => {
      try {
        const project = getAllowedProject(project_id);
        const wtDir = resolveTaskWorktree(project, task_id);
        if (!fs.existsSync(wtDir)) {
          return ok({ error: `Task worktree not found: ${wtDir}` });
        }
        const baseBranch = base_branch || project.defaultBranch;
        assertValidId(baseBranch, "base_branch");

        const branch = runGit(wtDir, ["rev-parse", "--abbrev-ref", "HEAD"]).stdout;
        const expectedBranch = `claude/${task_id}`;
        const errors = [];
        const warnings = [];

        if (branch !== expectedBranch) {
          errors.push(`Branch mismatch: on '${branch}', expected '${expectedBranch}'`);
        }

        const trackedChanged = runGit(wtDir, ["diff", "--name-only", `origin/${baseBranch}`], { allowFail: true })
          .stdout.split(/\r?\n/).filter(Boolean);
        const untracked = runGit(wtDir, ["ls-files", "--others", "--exclude-standard"])
          .stdout.split(/\r?\n/).filter(Boolean);
        const allChanged = [...new Set([...trackedChanged, ...untracked])];

        const diffText = runGit(wtDir, ["diff", "-U0", `origin/${baseBranch}`], { allowFail: true }).stdout;
        const secretFindings = scanDiffForSecrets(diffText, allChanged);
        for (const f of secretFindings) {
          errors.push(`${f.kind}: ${f.file} (${f.detail})`);
        }

        const deleted = runGit(wtDir, ["diff", "--diff-filter=D", "--name-only", `origin/${baseBranch}`], { allowFail: true })
          .stdout.split(/\r?\n/).filter(Boolean);
        if (deleted.length) {
          warnings.push(`Deleted files: ${deleted.join(", ")}`);
        }

        const lockfiles = allChanged.filter((f) => /(?:^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock)$/.test(f));
        if (lockfiles.length) {
          warnings.push(`Lockfile modified: ${lockfiles.join(", ")}`);
        }

        let testStatus = "skipped";
        let testOutput = "";
        if (run_tests && project.testCommand) {
          const tRes = runConfiguredTests(project, wtDir);
          testStatus = tRes.testStatus;
          testOutput = tRes.testOutput;
          if (testStatus === "failed") {
            errors.push(`Test command failed (exit ${tRes.exitCode})`);
          }
        }

        return ok({
          valid: errors.length === 0,
          task_id,
          project_id,
          branch,
          changed_files: allChanged,
          deleted_files: deleted,
          lockfiles_changed: lockfiles,
          secret_findings: secretFindings,
          test_status: testStatus,
          ...(testOutput && { test_output_tail: testOutput }),
          warnings,
          errors,
        });
      } catch (err) {
        return ok({ error: err.message });
      }
    }
  );

  server.registerTool(
    "github_publish_task",
    {
      title: "Commit and push a validated task branch to GitHub",
      description:
        "Requires explicit user approval (confirm_publish=true). Validates diff for secrets, " +
        "selectively stages files, commits on claude/<task_id> (never main), pushes without --force, " +
        "and verifies remote commit SHA on GitHub.",
      inputSchema: {
        project_id: z.string(),
        task_id: z.string(),
        commit_message: z.string(),
        confirm_publish: z.boolean().describe("Must be true only after explicit user approval"),
        files: z.array(z.string()).optional().describe("Specific relative files to stage; omit for all safe changes"),
        run_tests: z.boolean().optional(),
      },
    },
    async ({ project_id, task_id, commit_message, confirm_publish, files, run_tests = true }) => {
      if (confirm_publish !== true) {
        return ok({
          status: "waiting_for_approval",
          error: "confirm_publish=true is required after explicit user approval before committing/pushing.",
        });
      }
      try {
        const project = getAllowedProject(project_id);
        const wtDir = resolveTaskWorktree(project, task_id);
        if (!fs.existsSync(wtDir)) {
          return ok({ error: `Task worktree not found: ${wtDir}` });
        }
        const expectedBranch = `claude/${task_id}`;
        const curBranch = runGit(wtDir, ["rev-parse", "--abbrev-ref", "HEAD"]).stdout;
        if (curBranch === "main" || curBranch === "master" || curBranch !== expectedBranch) {
          return ok({ error: `Refusing to publish from branch '${curBranch}' (expected '${expectedBranch}')` });
        }

        // Pre-stage validation
        const untracked = runGit(wtDir, ["ls-files", "--others", "--exclude-standard"]).stdout.split(/\r?\n/).filter(Boolean);
        const modified = runGit(wtDir, ["diff", "--name-only"]).stdout.split(/\r?\n/).filter(Boolean);
        const candidateFiles = files?.length ? files : [...new Set([...modified, ...untracked])];

        for (const f of candidateFiles) {
          const reason = isForbiddenRepoFile(f);
          if (reason) {
            return ok({ error: `Refusing to stage '${f}': ${reason}` });
          }
          const resolved = realPathResolve(path.join(wtDir, f));
          if (!isPathInside(resolved, wtDir)) {
            return ok({ error: `Refusing file outside worktree: ${f}` });
          }
        }

        if (files?.length) {
          runGit(wtDir, ["add", "--", ...files]);
        } else if (candidateFiles.length) {
          runGit(wtDir, ["add", "--", ...candidateFiles]);
        }

        const stagedFiles = runGit(wtDir, ["diff", "--cached", "--name-only"]).stdout.split(/\r?\n/).filter(Boolean);
        const stagedDiff = runGit(wtDir, ["diff", "--cached", "-U0"]).stdout;
        const secretFindings = scanDiffForSecrets(stagedDiff, stagedFiles);
        if (secretFindings.length) {
          runGit(wtDir, ["reset", "HEAD"], { allowFail: true });
          return ok({ error: "Potential secret detected in staged diff; aborted commit.", secret_findings: secretFindings });
        }

        let testStatus = "skipped";
        if (run_tests && project.testCommand) {
          const tRes = runConfiguredTests(project, wtDir);
          testStatus = tRes.testStatus;
          if (testStatus === "failed") {
            return ok({ error: `Tests failed before publish (exit ${tRes.exitCode})`, test_status: testStatus });
          }
        }

        if (stagedFiles.length) {
          runGit(wtDir, ["commit", "-m", commit_message]);
        }

        const localSha = runGit(wtDir, ["rev-parse", "HEAD"]).stdout;
        const baseSha = runGit(wtDir, ["rev-parse", `origin/${project.defaultBranch}`], { allowFail: true }).stdout;
        if (localSha === baseSha) {
          return ok({ error: "No commits to push (HEAD equals base branch)." });
        }

        runGit(wtDir, ["push", "-u", "origin", expectedBranch]);
        const lsRemote = runGit(wtDir, ["ls-remote", "origin", `refs/heads/${expectedBranch}`]).stdout;
        const remoteSha = lsRemote.split(/\s+/)[0] || null;
        if (!remoteSha || remoteSha !== localSha) {
          return ok({ error: `Remote SHA verification failed (local=${localSha}, remote=${remoteSha})` });
        }

        const changedFiles = runGit(wtDir, ["diff-tree", "--no-commit-id", "--name-only", "-r", localSha])
          .stdout.split(/\r?\n/).filter(Boolean);

        await mutate((b) => {
          for (const t of b.tasks || []) {
            if (t.id === task_id || t.branch === expectedBranch || (t.cwd && realPathResolve(t.cwd) === realPathResolve(wtDir))) {
              t.status = "pushed";
              t.workflow_state = "pushed";
              t.commit_sha = localSha;
              t.branch = expectedBranch;
              t.repository = project.repository;
              t.updated = Date.now();
            }
          }
          logEvent(b, agentName(), "github.pushed", `${project_id}:${expectedBranch} @ ${localSha.slice(0, 8)}`);
        });

        return ok({
          task_id,
          status: "pushed",
          repository: project.repository,
          branch: expectedBranch,
          commit_sha: localSha,
          changed_files: changedFiles,
          test_status: testStatus,
        });
      } catch (err) {
        return ok({ error: err.message });
      }
    }
  );

  server.registerTool(
    "github_create_pr",
    {
      title: "Create a Pull Request for a pushed task branch (never auto-merges)",
      description:
        "Create a GitHub Pull Request for claude/<task_id> via gh CLI or GITHUB_TOKEN if available, " +
        "or return the compare URL when only a repository git Deploy Key is configured. Never merges.",
      inputSchema: {
        project_id: z.string(),
        task_id: z.string(),
        title: z.string(),
        body: z.string().optional(),
        base_branch: z.string().optional(),
        draft: z.boolean().optional(),
      },
    },
    async ({ project_id, task_id, title, body = "", base_branch, draft = false }) => {
      try {
        const project = getAllowedProject(project_id);
        const wtDir = resolveTaskWorktree(project, task_id);
        const headBranch = `claude/${task_id}`;
        const baseBranch = base_branch || project.defaultBranch;
        assertValidId(baseBranch, "base_branch");

        const checkDir = fs.existsSync(wtDir) ? wtDir : project.vpsPath;
        const lsRemote = runGit(checkDir, ["ls-remote", "origin", `refs/heads/${headBranch}`]).stdout;
        const commitSha = lsRemote.split(/\s+/)[0] || null;
        if (!commitSha) {
          return ok({ error: `Remote branch ${headBranch} is not pushed to origin yet.` });
        }

        const repoBase = githubHttpsUrl(project.repository);
        const compareUrl = `${repoBase}/compare/${baseBranch}...${headBranch}?expand=1`;

        const ghCheck = spawnSync("gh", ["auth", "status"], { encoding: "utf8", windowsHide: true });
        if (ghCheck.status === 0) {
          const args = [
            "pr", "create",
            "--repo", project.repository,
            "--head", headBranch,
            "--base", baseBranch,
            "--title", title,
            "--body", body || `Automated task ${task_id} (${commitSha})`,
          ];
          if (draft) args.push("--draft");
          const prRes = spawnSync("gh", args, { cwd: checkDir, encoding: "utf8", windowsHide: true });
          if (prRes.status !== 0) {
            return ok({ error: `gh pr create failed: ${(prRes.stderr || prRes.stdout).trim()}` });
          }
          const prUrl = prRes.stdout.trim();
          await mutate((b) => {
            for (const t of b.tasks || []) {
              if (t.id === task_id || t.branch === headBranch) {
                t.pr_url = prUrl;
                t.updated = Date.now();
              }
            }
            logEvent(b, agentName(), "github.pr_created", `${project_id}:${headBranch} -> ${prUrl}`);
          });
          return ok({ pr_url: prUrl, head_branch: headBranch, base_branch: baseBranch, commit_sha: commitSha, status: "open" });
        }

        const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
        if (token) {
          const resp = await fetch(`https://api.github.com/repos/${project.repository}/pulls`, {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: "application/vnd.github+json",
              "User-Agent": "antigravity-mcp-server",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              title,
              body: body || `Automated task ${task_id} (${commitSha})`,
              head: headBranch,
              base: baseBranch,
              draft,
            }),
          });
          const data = await resp.json();
          if (!resp.ok) {
            return ok({ error: `GitHub API PR creation failed (${resp.status}): ${data.message || JSON.stringify(data)}` });
          }
          await mutate((b) => {
            for (const t of b.tasks || []) {
              if (t.id === task_id || t.branch === headBranch) {
                t.pr_url = data.html_url;
                t.updated = Date.now();
              }
            }
            logEvent(b, agentName(), "github.pr_created", `${project_id}:${headBranch} -> ${data.html_url}`);
          });
          return ok({
            pr_url: data.html_url,
            head_branch: headBranch,
            base_branch: baseBranch,
            commit_sha: commitSha,
            status: data.state,
          });
        }

        return ok({
          status: "manual_pr_required",
          note: "VPS uses a repository Deploy Key (git push only) and has no gh auth or GITHUB_TOKEN; open compare_url or create PR from Windows.",
          compare_url: compareUrl,
          head_branch: headBranch,
          base_branch: baseBranch,
          commit_sha: commitSha,
        });
      } catch (err) {
        return ok({ error: err.message });
      }
    }
  );

  server.registerTool(
    "github_cleanup_task",
    {
      title: "Safely remove a completed task worktree",
      description:
        "Remove a task's temporary Git Worktree directory only after confirming there are no " +
        "uncommitted changes and no unpushed commits. Requires confirm_cleanup=true.",
      inputSchema: {
        project_id: z.string(),
        task_id: z.string(),
        confirm_cleanup: z.boolean().optional(),
      },
    },
    async ({ project_id, task_id, confirm_cleanup = false }) => {
      if (confirm_cleanup !== true) {
        return ok({ error: "Pass confirm_cleanup=true to remove the task worktree." });
      }
      try {
        const project = getAllowedProject(project_id);
        const wtDir = resolveTaskWorktree(project, task_id);
        if (!fs.existsSync(wtDir)) {
          return ok({ cleaned: false, note: `Worktree already absent: ${wtDir}` });
        }
        const dirty = runGit(wtDir, ["status", "--porcelain"]).stdout;
        if (dirty) {
          return ok({ error: `Refusing cleanup: uncommitted changes present in ${wtDir}: ${dirty}` });
        }
        const taskBranch = `claude/${task_id}`;
        const localSha = runGit(wtDir, ["rev-parse", "HEAD"]).stdout;
        const baseSha = runGit(project.vpsPath, ["rev-parse", `origin/${project.defaultBranch}`], { allowFail: true }).stdout;
        if (localSha !== baseSha) {
          const remoteSha = runGit(wtDir, ["ls-remote", "origin", `refs/heads/${taskBranch}`]).stdout.split(/\s+/)[0] || "";
          if (remoteSha !== localSha) {
            return ok({ error: `Refusing cleanup: commit ${localSha} on ${taskBranch} is not pushed to origin` });
          }
        }
        runGit(project.vpsPath, ["worktree", "remove", wtDir]);
        runGit(project.vpsPath, ["worktree", "prune"]);
        await mutate((b) => logEvent(b, agentName(), "github.cleanup_task", `${project_id}:${task_id}`));
        return ok({ cleaned: true, project_id, task_id, removed_cwd: wtDir });
      } catch (err) {
        return ok({ error: err.message });
      }
    }
  );
}
