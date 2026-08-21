# Agent rules for OpenGPM

You write all the code in this project. A human reviews every diff, and
CI mechanically enforces the rules below. Violating them wastes a review
cycle — it will not get past the guard job.

## Hard rules
1. Only modify files listed in the ticket's `Files` section. Never touch
   another package. If the ticket appears to require it, STOP and say so.
2. Never modify or create `*_test.go` files, anything under `testdata/`,
   or anything under `internal/model/`. Tests and fixtures are the
   SPECIFICATION, not part of the work. CI rejects these changes.
   If a test seems wrong, STOP and say so — do not "fix" it.
3. Never add a dependency. Stdlib plus what is already in `go.mod`.
4. Never delete, skip, or `t.Skip()` a failing test.
5. If the ticket names an Oracle, the oracle's recorded behaviour
   OUTRANKS any specification, documentation, or knowledge you have.
   Oracles are captured from real systems. When you disagree with one,
   you are wrong. Say so and stop rather than adjusting the oracle.

## When you get stuck
After two failed attempts at the Accept command, STOP and report:
what you tried, what failed, and what you think the ticket is missing.
Do not try a third approach. A stuck ticket is usually an
underspecified ticket, and that is a human problem to fix.

## Definition of done
- The ticket's `Accept` command exits 0.
- The ticket's `Oracle` check passes at the stated threshold, if any.
- `go vet ./...` and `golangci-lint run` are clean.
- `gofmt -l .` outputs nothing.
- The diff touches only the ticket's `Files`.

## Style
- Return errors, never panic. These parsers read untrusted input.
- Wrap errors with `fmt.Errorf("parsing X: %w", err)`.
- No `interface{}`/`any` in exported signatures.
- Malformed input is an error value, not a log line and not a zero value.

## Domain warnings
- Registry.pol strings are UTF-16LE, sizes are in BYTES, and Microsoft's
  public documentation of this format contains known errors. Follow the
  ticket's gotchas over any spec you recall.
- This project runs on LINUX in a container. There is no Windows API, no
  PowerShell, no WMI, no registry, no DPAPI, no UNC path you can os.Open.
  If a solution requires any of those, it is wrong — say so and stop.
- All SYSVOL access goes through an fs.FS. Never call os.Open or filepath
  helpers on a `\\server\share` path.
- Never silently drop a setting you cannot parse. Mark it unresolved and
  pass it through. Dropping data is worse than showing it raw.
- If a ticket's gotchas contradict your prior knowledge of Group Policy,
  the gotchas win. They were verified against the specification.
