//! Identity persistence using redb.
//!
//! Stores resolved identities, type mappings, and embedding vectors
//! in an ACID-compliant embedded database. Loaded on tracker startup,
//! updated on observe(). Instance maps are NOT persisted (PIDs are ephemeral).
//!
//! Requires the `persist` feature flag.

#![cfg(feature = "persist")]

use crate::identity::{IdentityId, ResolvedIdentity, TypeKey};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use std::path::Path;

/// redb table definitions.
const IDENTITIES_TABLE: redb::TableDefinition<u64, &[u8]> =
    redb::TableDefinition::new("identities");
const TYPE_MAP_TABLE: redb::TableDefinition<&[u8], u64> = redb::TableDefinition::new("type_map");
const EMBEDDINGS_TABLE: redb::TableDefinition<u64, &[u8]> =
    redb::TableDefinition::new("embeddings");
const METADATA_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("metadata");

/// Persistent identity store backed by redb.
pub struct IdentityStore {
    db: redb::Database,
}

impl IdentityStore {
    /// Open or create a store at the given path.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = redb::Database::create(path).map_err(|e| StoreError::Open(e.to_string()))?;

        // Create tables if they don't exist
        let write_txn = db
            .begin_write()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        {
            let _ = write_txn
                .open_table(IDENTITIES_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            let _ = write_txn
                .open_table(TYPE_MAP_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            let _ = write_txn
                .open_table(EMBEDDINGS_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            let _ = write_txn
                .open_table(METADATA_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Commit(e.to_string()))?;

        Ok(Self { db })
    }

    /// Open a store using an in-memory backend (for tests).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let backend = redb::backends::InMemoryBackend::new();
        let db = redb::Database::builder()
            .create_with_backend(backend)
            .map_err(|e| StoreError::Open(e.to_string()))?;

        let write_txn = db
            .begin_write()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        {
            let _ = write_txn
                .open_table(IDENTITIES_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            let _ = write_txn
                .open_table(TYPE_MAP_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            let _ = write_txn
                .open_table(EMBEDDINGS_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            let _ = write_txn
                .open_table(METADATA_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Commit(e.to_string()))?;

        Ok(Self { db })
    }

    /// Save a resolved identity.
    pub fn save_identity(&self, identity: &ResolvedIdentity) -> Result<(), StoreError> {
        let encoded =
            bincode::serialize(identity).map_err(|e| StoreError::Serialize(e.to_string()))?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(IDENTITIES_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            table
                .insert(identity.identity_id, encoded.as_slice())
                .map_err(|e| StoreError::Write(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Commit(e.to_string()))?;

        Ok(())
    }

    /// Load all identities from the store.
    pub fn load_identities(&self) -> Result<Vec<ResolvedIdentity>, StoreError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        let table = read_txn
            .open_table(IDENTITIES_TABLE)
            .map_err(|e| StoreError::Table(e.to_string()))?;

        let mut identities = Vec::new();
        for entry in table.iter().map_err(|e| StoreError::Read(e.to_string()))? {
            let (_, value) = entry.map_err(|e| StoreError::Read(e.to_string()))?;
            let identity: ResolvedIdentity = bincode::deserialize(value.value())
                .map_err(|e| StoreError::Deserialize(e.to_string()))?;
            identities.push(identity);
        }

        Ok(identities)
    }

    /// Save a type key → identity ID mapping.
    pub fn save_type_mapping(
        &self,
        type_key: &TypeKey,
        identity_id: IdentityId,
    ) -> Result<(), StoreError> {
        let key_bytes =
            bincode::serialize(type_key).map_err(|e| StoreError::Serialize(e.to_string()))?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TYPE_MAP_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            table
                .insert(key_bytes.as_slice(), identity_id)
                .map_err(|e| StoreError::Write(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Commit(e.to_string()))?;

        Ok(())
    }

    /// Load all type key → identity ID mappings.
    pub fn load_type_mappings(&self) -> Result<Vec<(TypeKey, IdentityId)>, StoreError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        let table = read_txn
            .open_table(TYPE_MAP_TABLE)
            .map_err(|e| StoreError::Table(e.to_string()))?;

        let mut mappings = Vec::new();
        for entry in table.iter().map_err(|e| StoreError::Read(e.to_string()))? {
            let (key, value) = entry.map_err(|e| StoreError::Read(e.to_string()))?;
            let type_key: TypeKey = bincode::deserialize(key.value())
                .map_err(|e| StoreError::Deserialize(e.to_string()))?;
            mappings.push((type_key, value.value()));
        }

        Ok(mappings)
    }

    /// Save an embedding vector for an identity.
    pub fn save_embedding(
        &self,
        identity_id: IdentityId,
        embedding: &[f32],
    ) -> Result<(), StoreError> {
        let encoded =
            bincode::serialize(embedding).map_err(|e| StoreError::Serialize(e.to_string()))?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(EMBEDDINGS_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            table
                .insert(identity_id, encoded.as_slice())
                .map_err(|e| StoreError::Write(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Commit(e.to_string()))?;

        Ok(())
    }

    /// Load an embedding vector for an identity.
    pub fn load_embedding(&self, identity_id: IdentityId) -> Result<Option<Vec<f32>>, StoreError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        let table = read_txn
            .open_table(EMBEDDINGS_TABLE)
            .map_err(|e| StoreError::Table(e.to_string()))?;

        match table
            .get(identity_id)
            .map_err(|e| StoreError::Read(e.to_string()))?
        {
            Some(value) => {
                let embedding: Vec<f32> = bincode::deserialize(value.value())
                    .map_err(|e| StoreError::Deserialize(e.to_string()))?;
                Ok(Some(embedding))
            }
            None => Ok(None),
        }
    }

    /// Remove an identity and its associated data.
    pub fn remove_identity(&self, identity_id: IdentityId) -> Result<(), StoreError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        {
            let mut id_table = write_txn
                .open_table(IDENTITIES_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            let _ = id_table.remove(identity_id);

            let mut emb_table = write_txn
                .open_table(EMBEDDINGS_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            let _ = emb_table.remove(identity_id);
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Commit(e.to_string()))?;

        Ok(())
    }

    /// Save arbitrary metadata (e.g. graph state, config).
    pub fn save_metadata(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(METADATA_TABLE)
                .map_err(|e| StoreError::Table(e.to_string()))?;
            table
                .insert(key, value)
                .map_err(|e| StoreError::Write(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Commit(e.to_string()))?;

        Ok(())
    }

    /// Load metadata by key.
    pub fn load_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        let table = read_txn
            .open_table(METADATA_TABLE)
            .map_err(|e| StoreError::Table(e.to_string()))?;

        match table
            .get(key)
            .map_err(|e| StoreError::Read(e.to_string()))?
        {
            Some(value) => Ok(Some(value.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Number of stored identities.
    pub fn identity_count(&self) -> Result<usize, StoreError> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Transaction(e.to_string()))?;
        let table = read_txn
            .open_table(IDENTITIES_TABLE)
            .map_err(|e| StoreError::Table(e.to_string()))?;
        Ok(table.len().map_err(|e| StoreError::Read(e.to_string()))? as usize)
    }
}

/// Store error types.
#[derive(Debug)]
pub enum StoreError {
    Open(String),
    Transaction(String),
    Table(String),
    Commit(String),
    Write(String),
    Read(String),
    Serialize(String),
    Deserialize(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(e) => write!(f, "store open: {e}"),
            Self::Transaction(e) => write!(f, "transaction: {e}"),
            Self::Table(e) => write!(f, "table: {e}"),
            Self::Commit(e) => write!(f, "commit: {e}"),
            Self::Write(e) => write!(f, "write: {e}"),
            Self::Read(e) => write!(f, "read: {e}"),
            Self::Serialize(e) => write!(f, "serialize: {e}"),
            Self::Deserialize(e) => write!(f, "deserialize: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ProviderTag;
    use crate::identity::TypeKey;

    fn test_identity(id: u64) -> ResolvedIdentity {
        ResolvedIdentity {
            identity_id: id,
            type_key: TypeKey {
                signature_hash: 0xdeadbeef,
                sdk_hash: 100,
                model_hash: 200,
            },
            first_seen: "12:00:00".into(),
            last_seen: "12:01:00".into(),
            event_count: 10,
            label: "openai-python (gpt-4)".into(),
            active_instances: vec![],
            providers: vec![ProviderTag::OpenAI],
            behavioral_digest: Some(0xABCD),
            capability_hash: Some(0x1234),
            prompt_fingerprint: Some(0x5678),
        }
    }

    #[test]
    fn roundtrip_identity() {
        let store = IdentityStore::open_in_memory().unwrap();
        let identity = test_identity(42);

        store.save_identity(&identity).unwrap();
        let loaded = store.load_identities().unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].identity_id, 42);
        assert_eq!(loaded[0].label, "openai-python (gpt-4)");
        assert_eq!(loaded[0].behavioral_digest, Some(0xABCD));
        assert_eq!(loaded[0].capability_hash, Some(0x1234));
        assert_eq!(loaded[0].prompt_fingerprint, Some(0x5678));
    }

    #[test]
    fn roundtrip_type_mapping() {
        let store = IdentityStore::open_in_memory().unwrap();
        let tk = TypeKey {
            signature_hash: 0xCAFE,
            sdk_hash: 10,
            model_hash: 20,
        };

        store.save_type_mapping(&tk, 999).unwrap();
        let mappings = store.load_type_mappings().unwrap();

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].0, tk);
        assert_eq!(mappings[0].1, 999);
    }

    #[test]
    fn roundtrip_embedding() {
        let store = IdentityStore::open_in_memory().unwrap();
        let embedding = vec![1.0f32, 2.0, 3.0, 4.5];

        store.save_embedding(42, &embedding).unwrap();
        let loaded = store.load_embedding(42).unwrap();

        assert_eq!(loaded, Some(vec![1.0, 2.0, 3.0, 4.5]));
    }

    #[test]
    fn missing_embedding_returns_none() {
        let store = IdentityStore::open_in_memory().unwrap();
        let loaded = store.load_embedding(999).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn remove_identity_cleans_up() {
        let store = IdentityStore::open_in_memory().unwrap();
        let identity = test_identity(42);

        store.save_identity(&identity).unwrap();
        store.save_embedding(42, &[1.0, 2.0]).unwrap();
        assert_eq!(store.identity_count().unwrap(), 1);

        store.remove_identity(42).unwrap();
        assert_eq!(store.identity_count().unwrap(), 0);
        assert!(store.load_embedding(42).unwrap().is_none());
    }

    #[test]
    fn metadata_roundtrip() {
        let store = IdentityStore::open_in_memory().unwrap();

        store.save_metadata("version", b"1.0").unwrap();
        let loaded = store.load_metadata("version").unwrap();
        assert_eq!(loaded, Some(b"1.0".to_vec()));

        assert!(store.load_metadata("missing").unwrap().is_none());
    }

    #[test]
    fn multiple_identities() {
        let store = IdentityStore::open_in_memory().unwrap();
        store.save_identity(&test_identity(1)).unwrap();
        store.save_identity(&test_identity(2)).unwrap();
        store.save_identity(&test_identity(3)).unwrap();

        assert_eq!(store.identity_count().unwrap(), 3);
        let loaded = store.load_identities().unwrap();
        assert_eq!(loaded.len(), 3);
    }

    #[test]
    fn overwrite_identity() {
        let store = IdentityStore::open_in_memory().unwrap();
        let mut identity = test_identity(42);
        store.save_identity(&identity).unwrap();

        identity.event_count = 100;
        identity.label = "updated".into();
        store.save_identity(&identity).unwrap();

        let loaded = store.load_identities().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].event_count, 100);
        assert_eq!(loaded[0].label, "updated");
    }
}
