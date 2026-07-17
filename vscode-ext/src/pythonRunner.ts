import { spawn } from 'child_process';

export interface PythonRunResult {
  stdout: string;
  stderr: string;
  code: number;
}

export interface PythonRunOptions {
  args?: string[];
  /** Piped to the process's stdin, if given. Never pass user content as a CLI arg instead — arbitrary code can contain anything a shell would choke on. */
  stdin?: string;
  cwd?: string;
  pythonBin?: string;
}

/**
 * Runs `<pythonBin> <scriptPath> <args...>`, optionally piping `stdin` in,
 * and resolves with stdout/stderr/exit code. Never throws on a non-zero
 * exit — callers decide what a given script's exit codes mean. Only
 * rejects if the process itself couldn't be spawned at all (e.g. python
 * isn't on PATH).
 *
 * pythonBin defaults to 'python3', which is wrong on plenty of Windows
 * installs (often just 'python' there). This should come from a
 * `ctrlAltDelulu.pythonPath` VS Code setting once one exists — see
 * extension.ts's TODO.
 */
export function runPython(scriptPath: string, options: PythonRunOptions = {}): Promise<PythonRunResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(options.pythonBin ?? 'python3', [scriptPath, ...(options.args ?? [])], {
      cwd: options.cwd,
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => (stdout += d.toString()));
    proc.stderr.on('data', (d) => (stderr += d.toString()));

    proc.on('close', (code) => {
      resolve({ stdout, stderr, code: code ?? -1 });
    });

    proc.on('error', (err) => reject(err));

    if (options.stdin !== undefined) {
      proc.stdin.write(options.stdin);
    }
    proc.stdin.end();
  });
}

/**
 * Convenience wrapper for the scripts that print a single JSON object as
 * their last line of stdout (checker.py, guard.py). Throws if the exit
 * code is non-zero or the output isn't valid JSON.
 */
export async function runPythonJson<T>(scriptPath: string, options: PythonRunOptions = {}): Promise<T> {
  const result = await runPython(scriptPath, options);
  if (result.code !== 0) {
    throw new Error(`${scriptPath} exited with code ${result.code}: ${result.stderr}`);
  }
  try {
    return JSON.parse(result.stdout) as T;
  } catch (err) {
    throw new Error(`Could not parse JSON from ${scriptPath}: ${err}\nstdout was: ${result.stdout}`);
  }
}
