//! Shared redb hash cache for guard and audit modules.

use redb::{ReadableDatabase, TableDefinition};
use tracing::warn;

const DB_FILE: &str = ".parry-guard.redb";

pub struct HashCache {
    db: redb::Database,
    table: TableDefinition<'static, &'static str, u64>,
}

impl HashCache {
    pub fn open(
        table: TableDefinition<'static, &'static str, u64>,
        runtime_dir: Option<&std::path::Path>,
    ) -> Option<Self> {
        let path = parry_guard_core::runtime_path(runtime_dir, DB_FILE)?;
        match redb::Database::create(&path) {
            Ok(db) => Some(Self { db, table }),
            Err(redb::DatabaseError::UpgradeRequired(_)) => {
                warn!("cache version mismatch, recreating");
                let _ = std::fs::remove_file(&path);
                redb::Database::create(&path)
                    .ok()
                    .map(|db| Self { db, table })
            }
            Err(e) => {
                warn!(%e, "cache open failed (scanning without cache)");
                None
            }
        }
    }

    pub fn is_cached(&self, key: &str, hash: u64) -> bool {
        let Ok(txn) = self.db.begin_read() else {
            return false;
        };
        let Ok(table) = txn.open_table(self.table) else {
            return false;
        };
        table
            .get(key)
            .ok()
            .flatten()
            .is_some_and(|v| v.value() == hash)
    }

    pub fn mark_clean(&self, key: &str, hash: u64) {
        let Ok(txn) = self.db.begin_write() else {
            return;
        };
        if let Ok(mut table) = txn.open_table(self.table) {
            let _ = table.insert(key, hash);
        }
        let _ = txn.commit();
    }
}
