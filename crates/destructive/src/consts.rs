//! Static command and flag arrays for destructive operation detection.

// === Category 1: Filesystem Destruction (unconditional) ===

/// Commands that are always destructive regardless of arguments.
pub(crate) const UNCONDITIONAL_DESTRUCTIVE: &[&str] =
    &["shred", "mkfs", "dd", "wipefs", "truncate", "srm"];

// === Category 2: Process / Service ===

pub(crate) const PROCESS_KILL: &[&str] = &["kill", "killall", "pkill", "xkill"];

pub(crate) const SYSTEMCTL_DESTRUCTIVE: &[&str] = &["stop", "disable", "mask"];
pub(crate) const LAUNCHCTL_DESTRUCTIVE: &[&str] = &["unload", "remove"];
pub(crate) const SERVICE_DESTRUCTIVE: &[&str] = &["stop"];

// Category 3 (Permissions: chmod/chown/chgrp) handled in bash.rs, no constants needed.

// === Category 4: Package Managers ===

/// (`command_name`, `destructive_subcommands`)
pub(crate) const PKG_MANAGER_DESTRUCTIVE: &[(&str, &[&str])] = &[
    ("brew", &["uninstall", "remove", "rm"]),
    ("apt", &["remove", "purge", "autoremove"]),
    ("apt-get", &["remove", "purge", "autoremove"]),
    ("pip", &["uninstall"]),
    ("pip3", &["uninstall"]),
    ("cargo", &["uninstall"]),
    ("bun", &["remove"]),
];

/// npm uninstall is only destructive with -g flag.
pub(crate) const NPM_GLOBAL_UNINSTALL: &[&str] = &["uninstall", "rm", "remove"];

// === Category 5: Git Destructive ===

pub(crate) const GIT_HISTORY_REWRITE: &[&str] = &["filter-branch", "filter-repo"];

// === Category 6: Database / Storage ===

pub(crate) const DB_CLI_COMMANDS: &[&str] = &["psql", "mysql", "sqlite3"];

pub(crate) const DB_DESTRUCTIVE_SQL: &[&str] = &[
    "drop table",
    "drop database",
    "drop schema",
    "truncate table",
    "truncate ",
];

pub(crate) const MONGO_CLI_COMMANDS: &[&str] = &["mongo", "mongosh"];

pub(crate) const MONGO_DESTRUCTIVE: &[&str] = &[
    "dropdatabase",
    ".drop()",
    "deletemany({})",
    "deletemany( {} )",
    "deletemany()",
];

pub(crate) const REDIS_CLI: &str = "redis-cli";

pub(crate) const REDIS_DESTRUCTIVE: &[&str] = &["flushall", "flushdb"];

pub(crate) const MONGORESTORE_DESTRUCTIVE: &[&str] = &["--drop"];

pub(crate) const LDB_DESTRUCTIVE: &[&str] = &["destroy"];

// Queues
pub(crate) const RABBITMQ_DESTRUCTIVE: &[&str] = &["delete_queue", "purge_queue"];
pub(crate) const CELERY_DESTRUCTIVE: &[&str] = &["purge"];

// === Category 7: Disk / Mount ===

pub(crate) const DISK_COMMANDS: &[&str] = &["umount", "diskutil", "fdisk", "parted"];

// === Category 8: Container / Orchestration ===

/// (`command`, `destructive_subcommand`)
pub(crate) const CONTAINER_DESTRUCTIVE: &[(&str, &[&str])] = &[
    ("kubectl", &["delete"]),
    ("terraform", &["destroy"]),
    ("helm", &["uninstall"]),
];

// === Category 9: System Admin ===

pub(crate) const FIREWALL_COMMANDS: &[&str] = &["iptables", "ip6tables"];
pub(crate) const FIREWALL_FLUSH_FLAGS: &[&str] = &["-F", "--flush"];

pub(crate) const NFT_FLUSH: &[&str] = &["flush"];

// === Category 10: Nix ===

/// Nix commands that are unconditionally destructive.
pub(crate) const NIX_UNCONDITIONAL: &[&str] = &["nix-collect-garbage"];

/// (`command`, `destructive_subcommand_prefix`)
pub(crate) const NIX_DESTRUCTIVE: &[(&str, &[&str])] = &[
    (
        "nix",
        &[
            "store gc",
            "store delete",
            "profile remove",
            "profile wipe-history",
        ],
    ),
    ("nix-store", &["--gc", "--delete"]),
    ("nix-env", &["-e", "--uninstall", "--delete-generations"]),
    ("nix-channel", &["--remove"]),
    ("nixos-rebuild", &["switch"]),
];

// === Category 11: Privilege Escalation ===

pub(crate) const PRIV_ESC: &[&str] = &["sudo", "su", "doas", "pkexec"];
