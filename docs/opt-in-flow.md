# Project scanning flow

Each repo is in one of three states: Unknown, Monitored, or Ignored. This page shows how hooks act on each state and how a repo moves between them.

## Default: monitor right away (`PARRY_ASK_ON_NEW_PROJECT=false`)

A new project becomes Monitored in its first session. There is no prompt, so protection starts immediately.

```
                    Session start
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
    Run audit       Set to           Skip
    (with cache)    Monitored,       (return success)
          |         run audit
          |         (with cache)
          v              |
    Show warnings        v
    (if any)       Show warnings
                   (if any)
```

## Ask first (`PARRY_ASK_ON_NEW_PROJECT=true`)

Parry scans the new project once, shows what it found, and lets you decide.

```
                    Session start
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
              | Claude asks the user:  |
              | "Enable injection      |
              |  scanning?"            |
              +------------------------+
                  |           |            |
                  v           v            v
                [Yes]        [No]      [No answer]
                  |           |            |
                  v           v            v
            Claude runs   Claude runs   Stays Unknown
            parry-guard   parry-guard   (asks again
            monitor       ignore         next session)
                  |           |
                  v           v
              Monitored    Ignored
                  |
                  v  (if there were findings)
              +------------------------+
              | Claude offers to help  |
              | fix the findings       |
              +------------------------+
```

## PreToolUse and PostToolUse

Only Monitored repos are scanned. Unknown repos are skipped because you haven't agreed to scanning yet.

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
    (7 checks for PreToolUse,
     output scan for PostToolUse)
```

## State changes

```
                    +-------------------+
                    |     Unknown       |
                    | (initial state)   |
                    +-------------------+
                       /           \
                      /             \
          monitor (or auto)        ignore
                    /                 \
                   v                   v
        +-------------+       +-------------+
        |  Monitored  | <---> |   Ignored   |
        |  (scanning) |       |  (no scan)  |
        +-------------+       +-------------+
                 monitor / ignore switch
                 between the two at any time

        reset (from any state) --> Unknown
```

All commands are `parry-guard <command>`.

## Settings and commands

| Setting | Effect |
|---|---|
| `PARRY_ASK_ON_NEW_PROJECT=false` (default) | Monitor new projects right away, no prompt |
| `PARRY_ASK_ON_NEW_PROJECT=true` | Ask before monitoring each new project |
| `PARRY_IGNORE_DIRS=/path/to/parent` | Skip every repo under these parent directories (comma-separated) |

| Command | Effect |
|---|---|
| `parry-guard monitor [path]` | Set the repo to Monitored (scanning on) |
| `parry-guard ignore [path]` | Set the repo to Ignored (scanning off) |
| `parry-guard reset [path]` | Clear state and caches, back to Unknown |
| `parry-guard status [path]` | Show the current state and re-run the audit for findings |
| `parry-guard repos` | List all known repos and their states |

`path` defaults to the current directory.
