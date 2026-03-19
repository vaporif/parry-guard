# Project Scanning Flow

## Default: Auto-Monitor (`PARRY_ASK_ON_NEW_PROJECT=false`)

New projects are automatically set to Monitored on first session. No prompt, immediate protection.

```
                    Session Start
                         |
                         v
               +-------------------+
               | UserPromptSubmit  |
               | hook fires        |
               +-------------------+
                         |
                         v
               +-------------------+
               | Under ignore dir? |--yes--> Skip (return success)
               +-------------------+
                         | no
                         v
               +-------------------+
               | Check repo state  |
               | in RepoDb         |
               +-------------------+
                    |    |    |
          +---------+    |    +---------+
          |              |              |
          v              v              v
     [Monitored]    [Unknown]      [Ignored]
          |              |              |
          v              v              v
    Run audit       Auto-set to      Skip
    (with cache)    Monitored,       (return success)
          |         run audit
          |         (with cache)
          v              |
    Show warnings        v
    (if any)       Show warnings
                   (if any)
```

## Prompt Mode (`PARRY_ASK_ON_NEW_PROJECT=true`)

Restores the ask-first behavior: scan once, show findings, ask user to decide.

```
                    Session Start
                         |
                         v
               +-------------------+
               | UserPromptSubmit  |
               | hook fires        |
               +-------------------+
                         |
                         v
               +-------------------+
               | Under ignore dir? |--yes--> Skip (return success)
               +-------------------+
                         | no
                         v
               +-------------------+
               | Check repo state  |
               | in RepoDb         |
               +-------------------+
                    |    |    |
          +---------+    |    +---------+
          |              |              |
          v              v              v
     [Monitored]    [Unknown]      [Ignored]
          |              |              |
          v              v              v
    Run audit       Run audit        Skip
    (with cache)    (bypass cache)   (return success)
          |              |
          v              v
    Normal flow     Return additionalContext
    (no prompt)     with findings + instructions
                         |
                         v
              +------------------------+
              | Claude asks user:      |
              | "Enable injection      |
              |  scanning?"            |
              +------------------------+
                    |           |
                    v           v
               [Yes]         [No]          [No answer]
                    |           |                |
                    v           v                v
              Claude runs  Claude runs     Stays Unknown
              `parry       `parry          (retries next
               monitor`     ignore`         session)
                    |           |
                    v           v
              Monitored     Ignored
                    |
                    v (if findings existed)
              +------------------------+
              | Claude offers to help  |
              | fix findings           |
              +------------------------+
```

## PreToolUse / PostToolUse Flow

```
               PreToolUse or PostToolUse
               hook fires
                         |
                         v
               +-------------------+
               | Under ignore dir? |--yes--> Skip (return success)
               +-------------------+
                         | no
                         v
               +-------------------+
               | Check repo state  |
               +-------------------+
                    |    |    |
          +---------+    |    +---------+
          |              |              |
          v              v              v
     [Monitored]    [Unknown]      [Ignored]
          |              |              |
          v              v              v
    Run all         Skip all        Skip all
    security        scanning        scanning
    layers          (no consent)
          |
          v
    Normal scan
    (7 layers for PreToolUse,
     output scan for PostToolUse)
```

## State Machine

```
                    +-------------------+
                    |     Unknown       |
                    | (initial state)   |
                    +-------------------+
                       /           \
                      /             \
          parry monitor          parry ignore
          (or auto-monitor)
                    /                 \
                   v                   v
        +-------------+       +-------------+
        |  Monitored  |       |   Ignored   |
        |  (scanning  |       |  (no scan)  |
        |   active)   |       |             |
        +-------------+       +-------------+
               |   ^               |   ^
               |   |               |   |
        parry  |   | parry  parry  |   | parry
        ignore |   | monitor ignore|   | monitor
               v   |               v   |
        +-------------+       +-------------+
        |   Ignored   |       |  Monitored  |
        +-------------+       +-------------+

        parry reset (from any state) --> Unknown
```

## Configuration

| Setting | Effect |
|---|---|
| `PARRY_ASK_ON_NEW_PROJECT=false` (default) | Auto-monitor new projects, no prompt |
| `PARRY_ASK_ON_NEW_PROJECT=true` | Ask user before monitoring each new project |
| `PARRY_IGNORE_DIRS=/path/to/parent` | Skip all repos under these parent directories (comma-separated) |
| `parry-guard ignore <path>` | Opt out of scanning for a specific repo |
| `parry-guard monitor <path>` | Opt in to scanning for a specific repo |

## CLI Commands

| Command | Effect |
|---|---|
| `parry monitor [path]` | Set repo to Monitored (enable scanning) |
| `parry ignore [path]` | Set repo to Ignored (disable scanning) |
| `parry reset [path]` | Clear state + caches, back to Unknown |
| `parry status [path]` | Show current state, re-run audit for findings |
| `parry repos` | List all known repos and their states |
