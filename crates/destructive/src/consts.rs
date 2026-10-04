//! Static command and flag arrays for destructive operation detection.

/// Destructive regardless of arguments.
pub(crate) const UNCONDITIONAL_DESTRUCTIVE: &[&str] =
    &["shred", "mkfs", "dd", "wipefs", "truncate", "srm"];

pub(crate) const PROCESS_KILL: &[&str] = &["kill", "killall", "pkill", "xkill"];

pub(crate) const SYSTEMCTL_DESTRUCTIVE: &[&str] = &["stop", "disable", "mask"];
pub(crate) const LAUNCHCTL_DESTRUCTIVE: &[&str] = &["unload", "remove"];
pub(crate) const SERVICE_DESTRUCTIVE: &[&str] = &["stop"];

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

/// Destructive only with `-g`.
pub(crate) const NPM_GLOBAL_UNINSTALL: &[&str] = &["uninstall", "rm", "remove"];

pub(crate) const GIT_HISTORY_REWRITE: &[&str] = &["filter-branch", "filter-repo"];

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

pub(crate) const RABBITMQ_DESTRUCTIVE: &[&str] = &["delete_queue", "purge_queue"];
pub(crate) const CELERY_DESTRUCTIVE: &[&str] = &["purge"];

pub(crate) const DISK_COMMANDS: &[&str] = &["umount", "diskutil", "fdisk", "parted"];

/// (`command`, `destructive_subcommand`)
pub(crate) const CONTAINER_DESTRUCTIVE: &[(&str, &[&str])] = &[
    ("kubectl", &["delete"]),
    ("terraform", &["destroy"]),
    ("helm", &["uninstall"]),
];

pub(crate) const FIREWALL_COMMANDS: &[&str] = &["iptables", "ip6tables"];
pub(crate) const FIREWALL_FLUSH_FLAGS: &[&str] = &["-F", "--flush"];

pub(crate) const NFT_FLUSH: &[&str] = &["flush"];

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

pub(crate) const PRIV_ESC: &[&str] = &["sudo", "su", "doas", "pkexec"];

// Command wrappers

/// Commands that run another command: (`wrapper`, `options_taking_a_value`, `operands_before_command`).
pub(crate) const COMMAND_WRAPPERS: &[(&str, &[&str], usize)] = &[
    ("command", &[], 0),
    ("exec", &["-a"], 0),
    ("env", &["-u", "--unset", "-C", "--chdir"], 0),
    ("nice", &["-n", "--adjustment"], 0),
    ("nohup", &[], 0),
    ("time", &[], 0),
    ("timeout", &["-s", "--signal", "-k", "--kill-after"], 1),
    (
        "stdbuf",
        &["-i", "-o", "-e", "--input", "--output", "--error"],
        0,
    ),
    ("setsid", &[], 0),
    (
        "ionice",
        &[
            "-c",
            "--class",
            "-n",
            "--classdata",
            "-p",
            "--pid",
            "-P",
            "--pgid",
            "-u",
            "--uid",
        ],
        0,
    ),
    (
        "xargs",
        &[
            "-a",
            "--arg-file",
            "-d",
            "--delimiter",
            "-E",
            "-I",
            "-L",
            "--max-lines",
            "-n",
            "--max-args",
            "-P",
            "--max-procs",
            "-s",
            "--max-chars",
        ],
        0,
    ),
];
