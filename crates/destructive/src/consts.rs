//! Static command and flag arrays for destructive operation detection.

// === Category 1: Filesystem Destruction (unconditional) ===

/// Commands that are always destructive regardless of arguments.
pub const UNCONDITIONAL_DESTRUCTIVE: &[&str] =
    &["shred", "mkfs", "dd", "wipefs", "truncate", "srm"];

// === Category 2: Process / Service ===

pub const PROCESS_KILL: &[&str] = &["kill", "killall", "pkill", "xkill"];

pub const SYSTEMCTL_DESTRUCTIVE: &[&str] = &["stop", "disable", "mask"];
pub const LAUNCHCTL_DESTRUCTIVE: &[&str] = &["unload", "remove"];
pub const SERVICE_DESTRUCTIVE: &[&str] = &["stop"];

// Category 3 (Permissions: chmod/chown/chgrp) handled in bash.rs -no constants needed.

// === Category 4: Package Managers ===

/// (`command_name`, `destructive_subcommands`)
pub const PKG_MANAGER_DESTRUCTIVE: &[(&str, &[&str])] = &[
    ("brew", &["uninstall", "remove", "rm"]),
    ("apt", &["remove", "purge", "autoremove"]),
    ("apt-get", &["remove", "purge", "autoremove"]),
    ("pip", &["uninstall"]),
    ("pip3", &["uninstall"]),
    ("cargo", &["uninstall"]),
    ("bun", &["remove"]),
];

/// npm uninstall is only destructive with -g flag.
pub const NPM_GLOBAL_UNINSTALL: &[&str] = &["uninstall", "rm", "remove"];

// === Category 5: Git Destructive ===

pub const GIT_HISTORY_REWRITE: &[&str] = &["filter-branch", "filter-repo"];

// === Category 6: Database / Storage ===

pub const DB_CLI_COMMANDS: &[&str] = &["psql", "mysql", "sqlite3"];

pub const DB_DESTRUCTIVE_SQL: &[&str] = &[
    "drop table",
    "drop database",
    "drop schema",
    "truncate table",
    "truncate ",
];

pub const MONGO_CLI_COMMANDS: &[&str] = &["mongo", "mongosh"];

pub const MONGO_DESTRUCTIVE: &[&str] = &[
    "dropdatabase",
    ".drop()",
    "deletemany({})",
    "deletemany( {} )",
    "deletemany()",
];

pub const REDIS_CLI: &str = "redis-cli";

pub const REDIS_DESTRUCTIVE: &[&str] = &["flushall", "flushdb"];

pub const MONGORESTORE_DESTRUCTIVE: &[&str] = &["--drop"];

pub const LDB_DESTRUCTIVE: &[&str] = &["destroy"];

// Queues
pub const RABBITMQ_DESTRUCTIVE: &[&str] = &["delete_queue", "purge_queue"];
pub const CELERY_DESTRUCTIVE: &[&str] = &["purge"];

// === Category 7: Disk / Mount ===

pub const DISK_COMMANDS: &[&str] = &["umount", "diskutil", "fdisk", "parted"];

// === Category 8: Container / Orchestration ===

/// (`command`, `destructive_subcommand`)
pub const CONTAINER_DESTRUCTIVE: &[(&str, &[&str])] = &[
    ("kubectl", &["delete"]),
    ("terraform", &["destroy"]),
    ("helm", &["uninstall"]),
];

// === Category 9: System Admin ===

pub const FIREWALL_COMMANDS: &[&str] = &["iptables", "ip6tables"];
pub const FIREWALL_FLUSH_FLAGS: &[&str] = &["-F", "--flush"];

pub const NFT_FLUSH: &[&str] = &["flush"];

// === Category 10: Nix ===

/// Nix commands that are unconditionally destructive.
pub const NIX_UNCONDITIONAL: &[&str] = &["nix-collect-garbage"];

/// (`command`, `destructive_subcommand_prefix`)
pub const NIX_DESTRUCTIVE: &[(&str, &[&str])] = &[
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

pub const PRIV_ESC: &[&str] = &["sudo", "su", "doas", "pkexec"];
