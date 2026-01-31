//! Vector Storage Backend (MEM-004)
//!
//! This module provides a vector storage abstraction for semantic memory,
//! designed to integrate with LanceDB or similar vector databases. For
//! development and testing, an in-memory implementation is provided.
//!
//! # Architecture
//!
//! The vector storage follows the VAK Cryptographic Memory Fabric design:
//! - Stores embeddings with associated metadata and content
//! - Supports approximate nearest neighbor (ANN) search
//! - Provides batch operations for efficiency
//! - Tracks version information for each entry
//!
//! # Example
//! ```rust
//! use vak::memory::vector_store::{VectorStore, VectorEntry, InMemoryVectorStore, VectorStoreConfig};
//!
//! let config = VectorStoreConfig::default();
//! let mut store = InMemoryVectorStore::new(config);
//!
//! // Store an entry with embedding
//! let entry = VectorEntry::new("doc1", b"Hello world".to_vec(), vec![0.1, 0.2, 0.3]);
//! store.insert(entry).unwrap();
//!
//! // Search by similarity
//! let query = vec![0.1, 0.2, 0.3];
//! let results = store.search(&query, 5, None).unwrap();
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during vector storage operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VectorStoreError {
    /// Entry not found
    EntryNotFound(String),
    /// Duplicate entry ID
    DuplicateEntry(String),
    /// Invalid embedding dimension
    DimensionMismatch { expected: usize, actual: usize },
    /// Collection not found
    CollectionNotFound(String),
    /// Backend connection error
    ConnectionError(String),
    /// Query error
    QueryError(String),
    /// Serialization error
    SerializationError(String),
    /// Index not ready
    IndexNotReady,
}

impl std::fmt::Display for VectorStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VectorStoreError::EntryNotFound(id) => {
                write!(f, "Entry not found: {}", id)
            }
            VectorStoreError::DuplicateEntry(id) => {
                write!(f, "Duplicate entry: {}", id)
            }
            VectorStoreError::DimensionMismatch { expected, actual } => {
                write!(
                    f,
                    "Embedding dimension mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            VectorStoreError::CollectionNotFound(name) => {
                write!(f, "Collection not found: {}", name)
            }
            VectorStoreError::ConnectionError(msg) => {
                write!(f, "Connection error: {}", msg)
            }
            VectorStoreError::QueryError(msg) => {
                write!(f, "Query error: {}", msg)
            }
            VectorStoreError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            VectorStoreError::IndexNotReady => {
                write!(f, "Index not ready")
            }
        }
    }
}

impl std::error::Error for VectorStoreError {}

/// Result type for vector storage operations
pub type VectorStoreResult<T> = Result<T, VectorStoreError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for vector storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStoreConfig {
    /// Expected embedding dimension (0 = auto-detect)
    pub embedding_dimension: usize,
    /// Distance metric to use
    pub distance_metric: DistanceMetric,
    /// Default number of results to return
    pub default_top_k: usize,
    /// Whether to normalize embeddings before storage
    pub normalize_embeddings: bool,
    /// Index type for search
    pub index_type: IndexType,
    /// Minimum similarity score threshold (0.0 to 1.0)
    pub min_similarity: f32,
}

impl Default for VectorStoreConfig {
    fn default() -> Self {
        Self {
            embedding_dimension: 0, // Auto-detect
            distance_metric: DistanceMetric::Cosine,
            default_top_k: 10,
            normalize_embeddings: true,
            index_type: IndexType::Flat,
            min_similarity: 0.0,
        }
    }
}

impl VectorStoreConfig {
    /// Set the embedding dimension
    pub fn with_dimension(mut self, dim: usize) -> Self {
        self.embedding_dimension = dim;
        self
    }

    /// Set the distance metric
    pub fn with_metric(mut self, metric: DistanceMetric) -> Self {
        self.distance_metric = metric;
        self
    }

    /// Set the default top_k
    pub fn with_default_top_k(mut self, k: usize) -> Self {
        self.default_top_k = k;
        self
    }

    /// Set minimum similarity threshold
    pub fn with_min_similarity(mut self, min: f32) -> Self {
        self.min_similarity = min;
        self
    }
}

/// Distance metrics for similarity search
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DistanceMetric {
    /// Cosine similarity (default)
    Cosine,
    /// Euclidean distance (L2)
    Euclidean,
    /// Dot product
    DotProduct,
    /// Manhattan distance (L1)
    Manhattan,
}

impl DistanceMetric {
    /// Compute distance/similarity between two vectors
    pub fn compute(&self, a: &[f32], b: &[f32]) -> f32 {
        match self {
            DistanceMetric::Cosine => cosine_similarity(a, b),
            DistanceMetric::Euclidean => 1.0 / (1.0 + euclidean_distance(a, b)),
            DistanceMetric::DotProduct => dot_product(a, b),
            DistanceMetric::Manhattan => 1.0 / (1.0 + manhattan_distance(a, b)),
        }
    }
}

/// Index types for search optimization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndexType {
    /// Flat index (exact search)
    Flat,
    /// IVF (Inverted File) index for approximate search
    IvfFlat { num_partitions: usize },
    /// HNSW (Hierarchical Navigable Small World) index
    Hnsw { m: usize, ef_construction: usize },
}

// ============================================================================
// Vector Entry
// ============================================================================

/// A vector entry with embedding, content, and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorEntry {
    /// Unique identifier
    pub id: String,
    /// The original content (serialized)
    pub content: Vec<u8>,
    /// The embedding vector
    pub embedding: Vec<f32>,
    /// Metadata key-value pairs
    pub metadata: HashMap<String, MetadataValue>,
    /// When the entry was created
    pub created_at: DateTime<Utc>,
    /// When the entry was last updated
    pub updated_at: DateTime<Utc>,
    /// Version number for optimistic concurrency
    pub version: u64,
    /// Content hash for integrity verification
    pub content_hash: [u8; 32],
}

impl VectorEntry {
    /// Create a new vector entry
    pub fn new(id: impl Into<String>, content: Vec<u8>, embedding: Vec<f32>) -> Self {
        let content_hash = compute_sha256(&content);
        let now = Utc::now();
        Self {
            id: id.into(),
            content,
            embedding,
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
            version: 1,
            content_hash,
        }
    }

    /// Add metadata to the entry
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<MetadataValue>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get the embedding dimension
    pub fn dimension(&self) -> usize {
        self.embedding.len()
    }

    /// Verify the content hash
    pub fn verify(&self) -> bool {
        compute_sha256(&self.content) == self.content_hash
    }

    /// Update the content and embedding
    pub fn update(&mut self, content: Vec<u8>, embedding: Vec<f32>) {
        self.content_hash = compute_sha256(&content);
        self.content = content;
        self.embedding = embedding;
        self.updated_at = Utc::now();
        self.version += 1;
    }
}

/// Metadata value types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MetadataValue {
    /// String value
    String(String),
    /// Integer value
    Integer(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Boolean(bool),
    /// List of strings
    StringList(Vec<String>),
    /// Null value
    Null,
}

impl From<&str> for MetadataValue {
    fn from(s: &str) -> Self {
        MetadataValue::String(s.to_string())
    }
}

impl From<String> for MetadataValue {
    fn from(s: String) -> Self {
        MetadataValue::String(s)
    }
}

impl From<i64> for MetadataValue {
    fn from(i: i64) -> Self {
        MetadataValue::Integer(i)
    }
}

impl From<f64> for MetadataValue {
    fn from(f: f64) -> Self {
        MetadataValue::Float(f)
    }
}

impl From<bool> for MetadataValue {
    fn from(b: bool) -> Self {
        MetadataValue::Boolean(b)
    }
}

// ============================================================================
// Search Results
// ============================================================================

/// A search result with the entry and similarity score
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The matched entry
    pub entry: VectorEntry,
    /// Similarity score (0.0 to 1.0 for most metrics)
    pub score: f32,
}

/// Query filters for search
#[derive(Debug, Clone, Default)]
pub struct SearchFilter {
    /// Filter by metadata key-value pairs
    pub metadata_filters: Vec<MetadataFilter>,
    /// Filter by time range (created_at)
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Exclude specific IDs
    pub exclude_ids: Vec<String>,
}

impl SearchFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a metadata filter
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        op: FilterOp,
        value: MetadataValue,
    ) -> Self {
        self.metadata_filters.push(MetadataFilter {
            key: key.into(),
            op,
            value,
        });
        self
    }

    /// Add a time range filter
    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.time_range = Some((start, end));
        self
    }

    /// Exclude specific IDs
    pub fn exclude(mut self, ids: Vec<String>) -> Self {
        self.exclude_ids = ids;
        self
    }
}

/// A metadata filter condition
#[derive(Debug, Clone)]
pub struct MetadataFilter {
    /// The metadata key to filter on
    pub key: String,
    /// The comparison operator
    pub op: FilterOp,
    /// The value to compare against
    pub value: MetadataValue,
}

/// Filter operators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    /// Equal to
    Eq,
    /// Not equal to
    Ne,
    /// Greater than
    Gt,
    /// Greater than or equal to
    Gte,
    /// Less than
    Lt,
    /// Less than or equal to
    Lte,
    /// Contains (for strings/lists)
    Contains,
}

// ============================================================================
// Vector Store Trait
// ============================================================================

/// Trait for vector storage backends
pub trait VectorStore: Send + Sync {
    /// Insert a new entry
    fn insert(&mut self, entry: VectorEntry) -> VectorStoreResult<()>;

    /// Insert multiple entries
    fn insert_batch(&mut self, entries: Vec<VectorEntry>) -> VectorStoreResult<()>;

    /// Get an entry by ID
    fn get(&self, id: &str) -> VectorStoreResult<Option<VectorEntry>>;

    /// Update an existing entry
    fn update(&mut self, entry: VectorEntry) -> VectorStoreResult<()>;

    /// Delete an entry by ID
    fn delete(&mut self, id: &str) -> VectorStoreResult<bool>;

    /// Search by embedding similarity
    fn search(
        &self,
        query: &[f32],
        top_k: usize,
        filter: Option<SearchFilter>,
    ) -> VectorStoreResult<Vec<SearchResult>>;

    /// Get the number of entries
    fn count(&self) -> usize;

    /// Clear all entries
    fn clear(&mut self) -> VectorStoreResult<()>;

    /// Check if the store is empty
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Get the embedding dimension (0 if not set)
    fn dimension(&self) -> usize;
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

/// In-memory vector store implementation for development and testing
pub struct InMemoryVectorStore {
    /// Configuration
    config: VectorStoreConfig,
    /// Stored entries by ID
    entries: HashMap<String, VectorEntry>,
    /// Detected embedding dimension
    detected_dimension: Option<usize>,
}

impl InMemoryVectorStore {
    /// Create a new in-memory vector store
    pub fn new(config: VectorStoreConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            detected_dimension: None,
        }
    }

    /// Create with default configuration
    pub fn default_store() -> Self {
        Self::new(VectorStoreConfig::default())
    }

    /// Get the configuration
    pub fn config(&self) -> &VectorStoreConfig {
        &self.config
    }

    /// Normalize an embedding vector
    fn normalize(&self, embedding: &[f32]) -> Vec<f32> {
        if !self.config.normalize_embeddings {
            return embedding.to_vec();
        }

        let norm: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm == 0.0 {
            return embedding.to_vec();
        }

        embedding.iter().map(|x| x / norm).collect()
    }

    /// Check embedding dimension compatibility
    fn check_dimension(&mut self, dim: usize) -> VectorStoreResult<()> {
        if self.config.embedding_dimension > 0 {
            if dim != self.config.embedding_dimension {
                return Err(VectorStoreError::DimensionMismatch {
                    expected: self.config.embedding_dimension,
                    actual: dim,
                });
            }
        } else if let Some(detected) = self.detected_dimension {
            if dim != detected {
                return Err(VectorStoreError::DimensionMismatch {
                    expected: detected,
                    actual: dim,
                });
            }
        } else {
            self.detected_dimension = Some(dim);
        }
        Ok(())
    }

    /// Check if an entry matches the filter
    fn matches_filter(&self, entry: &VectorEntry, filter: &SearchFilter) -> bool {
        // Check excluded IDs
        if filter.exclude_ids.contains(&entry.id) {
            return false;
        }

        // Check time range
        if let Some((start, end)) = &filter.time_range {
            if entry.created_at < *start || entry.created_at > *end {
                return false;
            }
        }

        // Check metadata filters
        for mf in &filter.metadata_filters {
            let metadata_value = match entry.metadata.get(&mf.key) {
                Some(v) => v,
                None => return false,
            };

            let matches = match (&mf.op, metadata_value, &mf.value) {
                (FilterOp::Eq, a, b) => a == b,
                (FilterOp::Ne, a, b) => a != b,
                (FilterOp::Gt, MetadataValue::Integer(a), MetadataValue::Integer(b)) => a > b,
                (FilterOp::Gt, MetadataValue::Float(a), MetadataValue::Float(b)) => a > b,
                (FilterOp::Gte, MetadataValue::Integer(a), MetadataValue::Integer(b)) => a >= b,
                (FilterOp::Gte, MetadataValue::Float(a), MetadataValue::Float(b)) => a >= b,
                (FilterOp::Lt, MetadataValue::Integer(a), MetadataValue::Integer(b)) => a < b,
                (FilterOp::Lt, MetadataValue::Float(a), MetadataValue::Float(b)) => a < b,
                (FilterOp::Lte, MetadataValue::Integer(a), MetadataValue::Integer(b)) => a <= b,
                (FilterOp::Lte, MetadataValue::Float(a), MetadataValue::Float(b)) => a <= b,
                (FilterOp::Contains, MetadataValue::String(a), MetadataValue::String(b)) => {
                    a.contains(b.as_str())
                }
                (FilterOp::Contains, MetadataValue::StringList(a), MetadataValue::String(b)) => {
                    a.contains(b)
                }
                _ => false,
            };

            if !matches {
                return false;
            }
        }

        true
    }
}

impl VectorStore for InMemoryVectorStore {
    fn insert(&mut self, mut entry: VectorEntry) -> VectorStoreResult<()> {
        if self.entries.contains_key(&entry.id) {
            return Err(VectorStoreError::DuplicateEntry(entry.id.clone()));
        }

        self.check_dimension(entry.embedding.len())?;

        // Normalize embedding if configured
        entry.embedding = self.normalize(&entry.embedding);

        self.entries.insert(entry.id.clone(), entry);
        Ok(())
    }

    fn insert_batch(&mut self, entries: Vec<VectorEntry>) -> VectorStoreResult<()> {
        for entry in entries {
            self.insert(entry)?;
        }
        Ok(())
    }

    fn get(&self, id: &str) -> VectorStoreResult<Option<VectorEntry>> {
        Ok(self.entries.get(id).cloned())
    }

    fn update(&mut self, mut entry: VectorEntry) -> VectorStoreResult<()> {
        if !self.entries.contains_key(&entry.id) {
            return Err(VectorStoreError::EntryNotFound(entry.id.clone()));
        }

        self.check_dimension(entry.embedding.len())?;

        // Normalize embedding if configured
        entry.embedding = self.normalize(&entry.embedding);

        self.entries.insert(entry.id.clone(), entry);
        Ok(())
    }

    fn delete(&mut self, id: &str) -> VectorStoreResult<bool> {
        Ok(self.entries.remove(id).is_some())
    }

    fn search(
        &self,
        query: &[f32],
        top_k: usize,
        filter: Option<SearchFilter>,
    ) -> VectorStoreResult<Vec<SearchResult>> {
        // Normalize query if needed
        let normalized_query = self.normalize(query);

        // Calculate similarities for all entries
        let mut results: Vec<SearchResult> = self
            .entries
            .values()
            .filter(|entry| {
                filter
                    .as_ref()
                    .map(|f| self.matches_filter(entry, f))
                    .unwrap_or(true)
            })
            .map(|entry| {
                let score = self
                    .config
                    .distance_metric
                    .compute(&normalized_query, &entry.embedding);
                SearchResult {
                    entry: entry.clone(),
                    score,
                }
            })
            .filter(|result| result.score >= self.config.min_similarity)
            .collect();

        // Sort by score descending
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Take top_k
        results.truncate(top_k);

        Ok(results)
    }

    fn count(&self) -> usize {
        self.entries.len()
    }

    fn clear(&mut self) -> VectorStoreResult<()> {
        self.entries.clear();
        self.detected_dimension = None;
        Ok(())
    }

    fn dimension(&self) -> usize {
        self.config
            .embedding_dimension
            .max(self.detected_dimension.unwrap_or(0))
    }
}

impl std::fmt::Debug for InMemoryVectorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryVectorStore")
            .field("config", &self.config)
            .field("entry_count", &self.entries.len())
            .field("dimension", &self.dimension())
            .finish()
    }
}

// ============================================================================
// Collection Manager
// ============================================================================

/// Manages multiple vector collections
pub struct VectorCollectionManager {
    /// Collections by name
    collections: HashMap<String, InMemoryVectorStore>,
    /// Default configuration for new collections
    default_config: VectorStoreConfig,
}

impl VectorCollectionManager {
    /// Create a new collection manager
    pub fn new() -> Self {
        Self {
            collections: HashMap::new(),
            default_config: VectorStoreConfig::default(),
        }
    }

    /// Create with a default configuration
    pub fn with_default_config(config: VectorStoreConfig) -> Self {
        Self {
            collections: HashMap::new(),
            default_config: config,
        }
    }

    /// Create a new collection
    pub fn create_collection(
        &mut self,
        name: impl Into<String>,
        config: Option<VectorStoreConfig>,
    ) -> VectorStoreResult<()> {
        let name = name.into();
        if self.collections.contains_key(&name) {
            return Err(VectorStoreError::DuplicateEntry(name));
        }

        let store = InMemoryVectorStore::new(config.unwrap_or_else(|| self.default_config.clone()));
        self.collections.insert(name, store);
        Ok(())
    }

    /// Get a collection by name
    pub fn get_collection(&self, name: &str) -> Option<&InMemoryVectorStore> {
        self.collections.get(name)
    }

    /// Get a mutable collection by name
    pub fn get_collection_mut(&mut self, name: &str) -> Option<&mut InMemoryVectorStore> {
        self.collections.get_mut(name)
    }

    /// Delete a collection
    pub fn delete_collection(&mut self, name: &str) -> VectorStoreResult<()> {
        self.collections
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| VectorStoreError::CollectionNotFound(name.to_string()))
    }

    /// List all collection names
    pub fn list_collections(&self) -> Vec<&str> {
        self.collections.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of collections
    pub fn collection_count(&self) -> usize {
        self.collections.len()
    }
}

impl Default for VectorCollectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for VectorCollectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VectorCollectionManager")
            .field("collection_count", &self.collections.len())
            .field("collections", &self.list_collections())
            .finish()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute SHA-256 hash
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute cosine similarity
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }

    dot / (norm_a * norm_b)
}

/// Compute dot product
fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Compute Euclidean distance
fn euclidean_distance(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return f32::MAX;
    }
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f32>()
        .sqrt()
}

/// Compute Manhattan distance
fn manhattan_distance(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return f32::MAX;
    }
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).abs()).sum()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entry(id: &str, embedding: Vec<f32>) -> VectorEntry {
        VectorEntry::new(id, format!("content for {}", id).into_bytes(), embedding)
    }

    #[test]
    fn test_vector_entry_creation() {
        let entry = VectorEntry::new("test", b"content".to_vec(), vec![0.1, 0.2, 0.3]);
        assert_eq!(entry.id, "test");
        assert_eq!(entry.dimension(), 3);
        assert!(entry.verify());
    }

    #[test]
    fn test_vector_entry_with_metadata() {
        let entry = VectorEntry::new("test", b"content".to_vec(), vec![0.1, 0.2, 0.3])
            .with_metadata("type", "document")
            .with_metadata("score", 42i64);

        assert_eq!(
            entry.metadata.get("type"),
            Some(&MetadataValue::String("document".to_string()))
        );
        assert_eq!(
            entry.metadata.get("score"),
            Some(&MetadataValue::Integer(42))
        );
    }

    #[test]
    fn test_vector_store_insert_and_get() {
        let mut store = InMemoryVectorStore::default_store();
        let entry = create_test_entry("doc1", vec![0.1, 0.2, 0.3]);

        store.insert(entry.clone()).unwrap();

        let retrieved = store.get("doc1").unwrap().unwrap();
        assert_eq!(retrieved.id, "doc1");
    }

    #[test]
    fn test_vector_store_duplicate_insert() {
        let mut store = InMemoryVectorStore::default_store();
        let entry = create_test_entry("doc1", vec![0.1, 0.2, 0.3]);

        store.insert(entry.clone()).unwrap();
        let result = store.insert(entry);

        assert!(matches!(result, Err(VectorStoreError::DuplicateEntry(_))));
    }

    #[test]
    fn test_vector_store_dimension_mismatch() {
        let mut store = InMemoryVectorStore::default_store();
        store
            .insert(create_test_entry("doc1", vec![0.1, 0.2, 0.3]))
            .unwrap();

        let result = store.insert(create_test_entry("doc2", vec![0.1, 0.2]));

        assert!(matches!(
            result,
            Err(VectorStoreError::DimensionMismatch { .. })
        ));
    }

    #[test]
    fn test_vector_store_search() {
        let mut store = InMemoryVectorStore::default_store();

        store
            .insert(create_test_entry("doc1", vec![1.0, 0.0, 0.0]))
            .unwrap();
        store
            .insert(create_test_entry("doc2", vec![0.0, 1.0, 0.0]))
            .unwrap();
        store
            .insert(create_test_entry("doc3", vec![0.9, 0.1, 0.0]))
            .unwrap();

        let results = store.search(&[1.0, 0.0, 0.0], 2, None).unwrap();

        assert_eq!(results.len(), 2);
        // doc1 and doc3 should be most similar to [1, 0, 0]
        assert!(results[0].entry.id == "doc1" || results[0].entry.id == "doc3");
    }

    #[test]
    fn test_vector_store_search_with_filter() {
        let mut store = InMemoryVectorStore::default_store();

        store
            .insert(
                create_test_entry("doc1", vec![1.0, 0.0, 0.0]).with_metadata("category", "tech"),
            )
            .unwrap();
        store
            .insert(
                create_test_entry("doc2", vec![0.9, 0.1, 0.0]).with_metadata("category", "science"),
            )
            .unwrap();
        store
            .insert(
                create_test_entry("doc3", vec![0.8, 0.2, 0.0]).with_metadata("category", "tech"),
            )
            .unwrap();

        let filter = SearchFilter::new().with_metadata(
            "category",
            FilterOp::Eq,
            MetadataValue::from("tech"),
        );

        let results = store.search(&[1.0, 0.0, 0.0], 10, Some(filter)).unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| {
            r.entry.metadata.get("category") == Some(&MetadataValue::String("tech".to_string()))
        }));
    }

    #[test]
    fn test_vector_store_delete() {
        let mut store = InMemoryVectorStore::default_store();
        store
            .insert(create_test_entry("doc1", vec![0.1, 0.2, 0.3]))
            .unwrap();

        assert!(store.delete("doc1").unwrap());
        assert!(!store.delete("doc1").unwrap());
        assert!(store.get("doc1").unwrap().is_none());
    }

    #[test]
    fn test_vector_store_update() {
        let mut store = InMemoryVectorStore::default_store();
        let entry = create_test_entry("doc1", vec![0.1, 0.2, 0.3]);
        store.insert(entry).unwrap();

        let mut updated = create_test_entry("doc1", vec![0.4, 0.5, 0.6]);
        updated.version = 2;
        store.update(updated).unwrap();

        let retrieved = store.get("doc1").unwrap().unwrap();
        // Note: embeddings are normalized, so we check dimension instead
        assert_eq!(retrieved.dimension(), 3);
    }

    #[test]
    fn test_vector_store_clear() {
        let mut store = InMemoryVectorStore::default_store();
        store
            .insert(create_test_entry("doc1", vec![0.1, 0.2, 0.3]))
            .unwrap();
        store
            .insert(create_test_entry("doc2", vec![0.4, 0.5, 0.6]))
            .unwrap();

        assert_eq!(store.count(), 2);
        store.clear().unwrap();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_distance_metrics() {
        let a = [1.0, 0.0, 0.0];
        let b = [0.0, 1.0, 0.0];
        let c = [1.0, 0.0, 0.0];

        // Cosine
        assert!((cosine_similarity(&a, &c) - 1.0).abs() < 0.001);
        assert!((cosine_similarity(&a, &b) - 0.0).abs() < 0.001);

        // Euclidean
        assert!((euclidean_distance(&a, &c) - 0.0).abs() < 0.001);
        assert!((euclidean_distance(&a, &b) - 1.414).abs() < 0.01);

        // Dot product
        assert!((dot_product(&a, &c) - 1.0).abs() < 0.001);
        assert!((dot_product(&a, &b) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_search_filter_exclude() {
        let mut store = InMemoryVectorStore::default_store();
        store
            .insert(create_test_entry("doc1", vec![1.0, 0.0, 0.0]))
            .unwrap();
        store
            .insert(create_test_entry("doc2", vec![0.9, 0.1, 0.0]))
            .unwrap();

        let filter = SearchFilter::new().exclude(vec!["doc1".to_string()]);

        let results = store.search(&[1.0, 0.0, 0.0], 10, Some(filter)).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry.id, "doc2");
    }

    #[test]
    fn test_collection_manager() {
        let mut manager = VectorCollectionManager::new();

        manager.create_collection("docs", None).unwrap();
        manager.create_collection("images", None).unwrap();

        assert_eq!(manager.collection_count(), 2);
        assert!(manager.list_collections().contains(&"docs"));

        let docs = manager.get_collection_mut("docs").unwrap();
        docs.insert(create_test_entry("doc1", vec![0.1, 0.2, 0.3]))
            .unwrap();

        assert_eq!(manager.get_collection("docs").unwrap().count(), 1);

        manager.delete_collection("images").unwrap();
        assert_eq!(manager.collection_count(), 1);
    }

    #[test]
    fn test_config_builder() {
        let config = VectorStoreConfig::default()
            .with_dimension(384)
            .with_metric(DistanceMetric::Euclidean)
            .with_default_top_k(20)
            .with_min_similarity(0.5);

        assert_eq!(config.embedding_dimension, 384);
        assert_eq!(config.distance_metric, DistanceMetric::Euclidean);
        assert_eq!(config.default_top_k, 20);
        assert!((config.min_similarity - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_vector_store_error_display() {
        let err = VectorStoreError::EntryNotFound("test".to_string());
        assert!(format!("{}", err).contains("Entry not found"));

        let err = VectorStoreError::DimensionMismatch {
            expected: 3,
            actual: 5,
        };
        assert!(format!("{}", err).contains("dimension mismatch"));
    }

    #[test]
    fn test_batch_insert() {
        let mut store = InMemoryVectorStore::default_store();
        let entries = vec![
            create_test_entry("doc1", vec![0.1, 0.2, 0.3]),
            create_test_entry("doc2", vec![0.4, 0.5, 0.6]),
            create_test_entry("doc3", vec![0.7, 0.8, 0.9]),
        ];

        store.insert_batch(entries).unwrap();
        assert_eq!(store.count(), 3);
    }

    #[test]
    fn test_entry_update() {
        let mut entry = VectorEntry::new("test", b"original".to_vec(), vec![0.1, 0.2, 0.3]);
        assert_eq!(entry.version, 1);

        entry.update(b"updated".to_vec(), vec![0.4, 0.5, 0.6]);

        assert_eq!(entry.version, 2);
        assert_eq!(entry.content, b"updated");
        assert!(entry.verify());
    }

    #[test]
    fn test_min_similarity_filter() {
        let config = VectorStoreConfig::default().with_min_similarity(0.9);
        let mut store = InMemoryVectorStore::new(config);

        store
            .insert(create_test_entry("doc1", vec![1.0, 0.0, 0.0]))
            .unwrap();
        store
            .insert(create_test_entry("doc2", vec![0.5, 0.5, 0.0]))
            .unwrap();
        store
            .insert(create_test_entry("doc3", vec![0.0, 0.0, 1.0]))
            .unwrap();

        let results = store.search(&[1.0, 0.0, 0.0], 10, None).unwrap();

        // Only doc1 should have similarity >= 0.9
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry.id, "doc1");
    }

    #[test]
    fn test_normalization() {
        let config = VectorStoreConfig::default();
        let store = InMemoryVectorStore::new(config);

        let normalized = store.normalize(&[3.0, 4.0]);
        let expected_norm: f32 = 5.0;

        assert!((normalized[0] - 3.0 / expected_norm).abs() < 0.001);
        assert!((normalized[1] - 4.0 / expected_norm).abs() < 0.001);
    }
}
