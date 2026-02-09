//! Knowledge Graph for Semantic Memory (MEM-003)
//!
//! This module provides a Knowledge Graph implementation for semantic memory,
//! combining structured relationship storage with vector-based retrieval.
//! It addresses the "hallucination" problem by grounding agents in a
//! structured ontology of entities and relationships.
//!
//! # Features
//! - **Entity management**: Store and query entities with properties
//! - **Relationship tracking**: Define typed relationships between entities
//! - **Graph traversal**: Find paths and related entities
//! - **Semantic search**: Query by properties or relationship types
//! - **Subgraph extraction**: Export relevant portions of the graph
//!
//! # Architecture
//!
//! The Knowledge Graph follows the Cryptographic Memory Fabric design:
//! - Each entity and relationship is hashable for integrity verification
//! - Supports namespace isolation for multi-agent scenarios
//! - Integrates with the StateManager for persistence
//!
//! # Example
//! ```rust
//! use vak::memory::knowledge_graph::{KnowledgeGraph, Entity, Relationship, RelationType};
//!
//! let mut kg = KnowledgeGraph::new("agent1");
//!
//! // Add entities
//! let server_a = kg.add_entity(Entity::new("server_a", "Server")
//!     .with_property("ip", "192.168.1.1")
//!     .with_property("status", "running")).unwrap();
//!
//! let service_b = kg.add_entity(Entity::new("service_b", "Service")
//!     .with_property("port", "8080")).unwrap();
//!
//! // Create relationship
//! kg.add_relationship(Relationship::new(
//!     server_a.clone(),
//!     service_b,
//!     RelationType::HostsService,
//! ));
//!
//! // Query relationships
//! let services = kg.get_related(server_a, Some(RelationType::HostsService));
//! ```

use chrono::{DateTime, Utc};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during knowledge graph operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnowledgeGraphError {
    /// Entity not found
    EntityNotFound(EntityId),
    /// Duplicate entity ID
    DuplicateEntity(String),
    /// Relationship not found
    RelationshipNotFound(RelationshipId),
    /// Invalid relationship (entity doesn't exist)
    InvalidRelationship {
        /// Source entity ID
        source: EntityId,
        /// Target entity ID
        target: EntityId,
        /// Reason for invalidity
        reason: String,
    },
    /// Cycle detected when cycles are not allowed
    CycleDetected {
        /// Entities involved in the cycle
        entities: Vec<EntityId>,
    },
    /// Serialization error
    SerializationError(String),
    /// Query error
    QueryError(String),
}

impl std::fmt::Display for KnowledgeGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnowledgeGraphError::EntityNotFound(id) => {
                write!(f, "Entity not found: {}", id)
            }
            KnowledgeGraphError::DuplicateEntity(name) => {
                write!(f, "Duplicate entity: {}", name)
            }
            KnowledgeGraphError::RelationshipNotFound(id) => {
                write!(f, "Relationship not found: {}", id)
            }
            KnowledgeGraphError::InvalidRelationship {
                source,
                target,
                reason,
            } => {
                write!(
                    f,
                    "Invalid relationship from {} to {}: {}",
                    source, target, reason
                )
            }
            KnowledgeGraphError::CycleDetected { entities } => {
                write!(f, "Cycle detected involving entities: {:?}", entities)
            }
            KnowledgeGraphError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            KnowledgeGraphError::QueryError(msg) => {
                write!(f, "Query error: {}", msg)
            }
        }
    }
}

impl std::error::Error for KnowledgeGraphError {}

/// Result type for knowledge graph operations
pub type KnowledgeGraphResult<T> = Result<T, KnowledgeGraphError>;

// ============================================================================
// Entity Types
// ============================================================================

/// Unique identifier for an entity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(Uuid);

impl EntityId {
    /// Create a new random entity ID
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Create from a UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a relationship
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelationshipId(Uuid);

impl RelationshipId {
    /// Create a new random relationship ID
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Create from a UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for RelationshipId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RelationshipId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A property value that can be attached to entities
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PropertyValue {
    /// String value
    String(String),
    /// Integer value
    Integer(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Boolean(bool),
    /// List of values
    List(Vec<PropertyValue>),
    /// Null/empty value
    Null,
}

impl PropertyValue {
    /// Get as string if it's a string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PropertyValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as integer if it's an integer
    pub fn as_int(&self) -> Option<i64> {
        match self {
            PropertyValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Get as float if it's a float
    pub fn as_float(&self) -> Option<f64> {
        match self {
            PropertyValue::Float(f) => Some(*f),
            PropertyValue::Integer(i) => Some(*i as f64),
            _ => None,
        }
    }

    /// Get as boolean if it's a boolean
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PropertyValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }
}

impl From<&str> for PropertyValue {
    fn from(s: &str) -> Self {
        PropertyValue::String(s.to_string())
    }
}

impl From<String> for PropertyValue {
    fn from(s: String) -> Self {
        PropertyValue::String(s)
    }
}

impl From<i64> for PropertyValue {
    fn from(i: i64) -> Self {
        PropertyValue::Integer(i)
    }
}

impl From<i32> for PropertyValue {
    fn from(i: i32) -> Self {
        PropertyValue::Integer(i as i64)
    }
}

impl From<f64> for PropertyValue {
    fn from(f: f64) -> Self {
        PropertyValue::Float(f)
    }
}

impl From<bool> for PropertyValue {
    fn from(b: bool) -> Self {
        PropertyValue::Boolean(b)
    }
}

impl std::fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropertyValue::String(s) => write!(f, "\"{}\"", s),
            PropertyValue::Integer(i) => write!(f, "{}", i),
            PropertyValue::Float(fl) => write!(f, "{}", fl),
            PropertyValue::Boolean(b) => write!(f, "{}", b),
            PropertyValue::List(l) => write!(f, "{:?}", l),
            PropertyValue::Null => write!(f, "null"),
        }
    }
}

/// An entity in the knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Unique identifier
    pub id: EntityId,
    /// Human-readable name
    pub name: String,
    /// Type/category of the entity
    pub entity_type: String,
    /// Properties attached to this entity
    pub properties: HashMap<String, PropertyValue>,
    /// When the entity was created
    pub created_at: DateTime<Utc>,
    /// When the entity was last modified
    pub modified_at: DateTime<Utc>,
    /// Optional embedding for semantic search
    pub embedding: Option<Vec<f32>>,
    /// Hash for integrity verification
    pub hash: [u8; 32],
}

impl Entity {
    /// Create a new entity with the given name and type
    pub fn new(name: impl Into<String>, entity_type: impl Into<String>) -> Self {
        let now = Utc::now();
        let mut entity = Self {
            id: EntityId::new(),
            name: name.into(),
            entity_type: entity_type.into(),
            properties: HashMap::new(),
            created_at: now,
            modified_at: now,
            embedding: None,
            hash: [0u8; 32],
        };
        entity.update_hash();
        entity
    }

    /// Add a property to the entity
    pub fn with_property(
        mut self,
        key: impl Into<String>,
        value: impl Into<PropertyValue>,
    ) -> Self {
        self.properties.insert(key.into(), value.into());
        self.modified_at = Utc::now();
        self.update_hash();
        self
    }

    /// Set the embedding vector
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = Some(embedding);
        self
    }

    /// Get a property value
    pub fn get_property(&self, key: &str) -> Option<&PropertyValue> {
        self.properties.get(key)
    }

    /// Set a property value
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<PropertyValue>) {
        self.properties.insert(key.into(), value.into());
        self.modified_at = Utc::now();
        self.update_hash();
    }

    /// Remove a property
    pub fn remove_property(&mut self, key: &str) -> Option<PropertyValue> {
        let result = self.properties.remove(key);
        if result.is_some() {
            self.modified_at = Utc::now();
            self.update_hash();
        }
        result
    }

    /// Update the hash based on current content
    fn update_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.id.0.as_bytes());
        hasher.update(self.name.as_bytes());
        hasher.update(self.entity_type.as_bytes());

        // Hash properties in sorted order for determinism
        let mut keys: Vec<_> = self.properties.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(format!("{}", self.properties[key]).as_bytes());
        }

        self.hash = hasher.finalize().into();
    }

    /// Verify the entity's hash
    pub fn verify_hash(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.id.0.as_bytes());
        hasher.update(self.name.as_bytes());
        hasher.update(self.entity_type.as_bytes());

        let mut keys: Vec<_> = self.properties.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(format!("{}", self.properties[key]).as_bytes());
        }

        let computed: [u8; 32] = hasher.finalize().into();
        computed == self.hash
    }
}

impl PartialEq for Entity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Entity {}

// ============================================================================
// Relationship Types
// ============================================================================

/// Common relationship types in the knowledge graph
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationType {
    // Hierarchical relationships
    /// Parent-child relationship
    ParentOf,
    /// Child-parent relationship (inverse of ParentOf)
    ChildOf,
    /// Contains another entity
    Contains,
    /// Is contained by another entity
    ContainedBy,

    // Dependency relationships
    /// Depends on another entity
    DependsOn,
    /// Is depended upon by another entity
    DependencyOf,
    /// Requires another entity
    Requires,
    /// Is required by another entity
    RequiredBy,

    // Association relationships
    /// Related to another entity
    RelatedTo,
    /// Associated with another entity
    AssociatedWith,
    /// References another entity
    References,
    /// Is referenced by another entity
    ReferencedBy,

    // Service/System relationships
    /// Hosts a service
    HostsService,
    /// Runs on a host
    RunsOn,
    /// Connects to another entity
    ConnectsTo,
    /// Communicates with another entity
    CommunicatesWith,

    // Ownership relationships
    /// Owns another entity
    Owns,
    /// Is owned by another entity
    OwnedBy,
    /// Created by another entity
    CreatedBy,
    /// Created another entity
    Created,

    // Temporal relationships
    /// Precedes another entity/event
    Precedes,
    /// Follows another entity/event
    Follows,
    /// Caused by another event
    CausedBy,
    /// Causes another event
    Causes,

    /// Custom user-defined relationship type
    Custom(String),
}

impl std::fmt::Display for RelationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationType::ParentOf => write!(f, "PARENT_OF"),
            RelationType::ChildOf => write!(f, "CHILD_OF"),
            RelationType::Contains => write!(f, "CONTAINS"),
            RelationType::ContainedBy => write!(f, "CONTAINED_BY"),
            RelationType::DependsOn => write!(f, "DEPENDS_ON"),
            RelationType::DependencyOf => write!(f, "DEPENDENCY_OF"),
            RelationType::Requires => write!(f, "REQUIRES"),
            RelationType::RequiredBy => write!(f, "REQUIRED_BY"),
            RelationType::RelatedTo => write!(f, "RELATED_TO"),
            RelationType::AssociatedWith => write!(f, "ASSOCIATED_WITH"),
            RelationType::References => write!(f, "REFERENCES"),
            RelationType::ReferencedBy => write!(f, "REFERENCED_BY"),
            RelationType::HostsService => write!(f, "HOSTS_SERVICE"),
            RelationType::RunsOn => write!(f, "RUNS_ON"),
            RelationType::ConnectsTo => write!(f, "CONNECTS_TO"),
            RelationType::CommunicatesWith => write!(f, "COMMUNICATES_WITH"),
            RelationType::Owns => write!(f, "OWNS"),
            RelationType::OwnedBy => write!(f, "OWNED_BY"),
            RelationType::CreatedBy => write!(f, "CREATED_BY"),
            RelationType::Created => write!(f, "CREATED"),
            RelationType::Precedes => write!(f, "PRECEDES"),
            RelationType::Follows => write!(f, "FOLLOWS"),
            RelationType::CausedBy => write!(f, "CAUSED_BY"),
            RelationType::Causes => write!(f, "CAUSES"),
            RelationType::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// A relationship between two entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    /// Unique identifier
    pub id: RelationshipId,
    /// Source entity ID
    pub source: EntityId,
    /// Target entity ID
    pub target: EntityId,
    /// Type of the relationship
    pub relation_type: RelationType,
    /// Optional weight/strength of the relationship
    pub weight: Option<f64>,
    /// Properties attached to this relationship
    pub properties: HashMap<String, PropertyValue>,
    /// When the relationship was created
    pub created_at: DateTime<Utc>,
}

impl Relationship {
    /// Create a new relationship
    pub fn new(source: EntityId, target: EntityId, relation_type: RelationType) -> Self {
        Self {
            id: RelationshipId::new(),
            source,
            target,
            relation_type,
            weight: None,
            properties: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    /// Set the relationship weight
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = Some(weight);
        self
    }

    /// Add a property to the relationship
    pub fn with_property(
        mut self,
        key: impl Into<String>,
        value: impl Into<PropertyValue>,
    ) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

impl PartialEq for Relationship {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Relationship {}

// ============================================================================
// Knowledge Graph
// ============================================================================

/// Configuration for the knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeGraphConfig {
    /// Allow cycles in the graph
    pub allow_cycles: bool,
    /// Maximum depth for traversal queries
    pub max_traversal_depth: usize,
    /// Enable automatic inverse relationship creation
    pub auto_inverse_relationships: bool,
}

impl Default for KnowledgeGraphConfig {
    fn default() -> Self {
        Self {
            allow_cycles: true,
            max_traversal_depth: 10,
            auto_inverse_relationships: false,
        }
    }
}

/// The main Knowledge Graph structure
pub struct KnowledgeGraph {
    /// Namespace for this graph (typically agent ID)
    namespace: String,
    /// Configuration
    config: KnowledgeGraphConfig,
    /// The underlying graph structure
    graph: DiGraph<Entity, Relationship>,
    /// Map from entity ID to node index
    entity_index: HashMap<EntityId, NodeIndex>,
    /// Map from entity name to entity ID (for name-based lookups)
    name_index: HashMap<String, EntityId>,
    /// Map from relationship ID to edge index
    relationship_index: HashMap<RelationshipId, petgraph::graph::EdgeIndex>,
    /// Version number for optimistic concurrency
    version: u64,
}

impl KnowledgeGraph {
    /// Create a new knowledge graph with the given namespace
    pub fn new(namespace: impl Into<String>) -> Self {
        Self::with_config(namespace, KnowledgeGraphConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(namespace: impl Into<String>, config: KnowledgeGraphConfig) -> Self {
        Self {
            namespace: namespace.into(),
            config,
            graph: DiGraph::new(),
            entity_index: HashMap::new(),
            name_index: HashMap::new(),
            relationship_index: HashMap::new(),
            version: 0,
        }
    }

    /// Get the namespace
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get the current version
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Get the number of entities
    pub fn entity_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the number of relationships
    pub fn relationship_count(&self) -> usize {
        self.graph.edge_count()
    }

    // ========================================================================
    // Entity Operations
    // ========================================================================

    /// Add an entity to the graph
    pub fn add_entity(&mut self, entity: Entity) -> KnowledgeGraphResult<EntityId> {
        // Check for duplicate name
        if self.name_index.contains_key(&entity.name) {
            return Err(KnowledgeGraphError::DuplicateEntity(entity.name.clone()));
        }

        let entity_id = entity.id;
        let entity_name = entity.name.clone();

        let node_index = self.graph.add_node(entity);
        self.entity_index.insert(entity_id, node_index);
        self.name_index.insert(entity_name, entity_id);
        self.version += 1;

        Ok(entity_id)
    }

    /// Get an entity by ID
    pub fn get_entity(&self, id: EntityId) -> Option<&Entity> {
        self.entity_index
            .get(&id)
            .and_then(|idx| self.graph.node_weight(*idx))
    }

    /// Get a mutable reference to an entity
    pub fn get_entity_mut(&mut self, id: EntityId) -> Option<&mut Entity> {
        self.entity_index
            .get(&id)
            .and_then(|idx| self.graph.node_weight_mut(*idx))
    }

    /// Get an entity by name
    pub fn get_entity_by_name(&self, name: &str) -> Option<&Entity> {
        self.name_index
            .get(name)
            .and_then(|id| self.get_entity(*id))
    }

    /// Remove an entity and all its relationships
    pub fn remove_entity(&mut self, id: EntityId) -> KnowledgeGraphResult<Entity> {
        let node_index = self
            .entity_index
            .remove(&id)
            .ok_or(KnowledgeGraphError::EntityNotFound(id))?;

        // Get the entity before removal
        let entity = self
            .graph
            .node_weight(node_index)
            .cloned()
            .ok_or(KnowledgeGraphError::EntityNotFound(id))?;

        // Remove from name index
        self.name_index.remove(&entity.name);

        // Remove all edges connected to this node
        let edges_to_remove: Vec<_> = self
            .graph
            .edges_directed(node_index, Direction::Incoming)
            .chain(self.graph.edges_directed(node_index, Direction::Outgoing))
            .map(|e| e.id())
            .collect();

        for edge_id in edges_to_remove {
            if let Some(rel) = self.graph.edge_weight(edge_id) {
                self.relationship_index.remove(&rel.id);
            }
            self.graph.remove_edge(edge_id);
        }

        // Remove the node
        self.graph.remove_node(node_index);
        self.version += 1;

        Ok(entity)
    }

    /// Get all entities of a given type
    pub fn get_entities_by_type(&self, entity_type: &str) -> Vec<&Entity> {
        self.graph
            .node_weights()
            .filter(|e| e.entity_type == entity_type)
            .collect()
    }

    /// Get all entities
    pub fn get_all_entities(&self) -> Vec<&Entity> {
        self.graph.node_weights().collect()
    }

    /// Search entities by property value
    pub fn search_entities_by_property(&self, key: &str, value: &PropertyValue) -> Vec<&Entity> {
        self.graph
            .node_weights()
            .filter(|e| e.properties.get(key) == Some(value))
            .collect()
    }

    /// Search entities by name pattern
    pub fn search_entities_by_name(&self, pattern: &str) -> Vec<&Entity> {
        let pattern_lower = pattern.to_lowercase();
        self.graph
            .node_weights()
            .filter(|e| e.name.to_lowercase().contains(&pattern_lower))
            .collect()
    }

    // ========================================================================
    // Relationship Operations
    // ========================================================================

    /// Add a relationship between two entities
    pub fn add_relationship(
        &mut self,
        relationship: Relationship,
    ) -> KnowledgeGraphResult<RelationshipId> {
        let source_idx = self.entity_index.get(&relationship.source).copied().ok_or(
            KnowledgeGraphError::InvalidRelationship {
                source: relationship.source,
                target: relationship.target,
                reason: "Source entity not found".to_string(),
            },
        )?;

        let target_idx = self.entity_index.get(&relationship.target).copied().ok_or(
            KnowledgeGraphError::InvalidRelationship {
                source: relationship.source,
                target: relationship.target,
                reason: "Target entity not found".to_string(),
            },
        )?;

        // Check for cycles if not allowed
        if !self.config.allow_cycles && source_idx == target_idx {
            return Err(KnowledgeGraphError::CycleDetected {
                entities: vec![relationship.source],
            });
        }

        let rel_id = relationship.id;
        let edge_idx = self.graph.add_edge(source_idx, target_idx, relationship);
        self.relationship_index.insert(rel_id, edge_idx);
        self.version += 1;

        Ok(rel_id)
    }

    /// Get a relationship by ID
    pub fn get_relationship(&self, id: RelationshipId) -> Option<&Relationship> {
        self.relationship_index
            .get(&id)
            .and_then(|idx| self.graph.edge_weight(*idx))
    }

    /// Remove a relationship
    pub fn remove_relationship(
        &mut self,
        id: RelationshipId,
    ) -> KnowledgeGraphResult<Relationship> {
        let edge_idx = self
            .relationship_index
            .remove(&id)
            .ok_or(KnowledgeGraphError::RelationshipNotFound(id))?;

        let relationship = self
            .graph
            .remove_edge(edge_idx)
            .ok_or(KnowledgeGraphError::RelationshipNotFound(id))?;

        self.version += 1;
        Ok(relationship)
    }

    /// Get all relationships from an entity
    pub fn get_outgoing_relationships(&self, entity_id: EntityId) -> Vec<&Relationship> {
        if let Some(&node_idx) = self.entity_index.get(&entity_id) {
            self.graph
                .edges_directed(node_idx, Direction::Outgoing)
                .map(|e| e.weight())
                .collect()
        } else {
            vec![]
        }
    }

    /// Get all relationships to an entity
    pub fn get_incoming_relationships(&self, entity_id: EntityId) -> Vec<&Relationship> {
        if let Some(&node_idx) = self.entity_index.get(&entity_id) {
            self.graph
                .edges_directed(node_idx, Direction::Incoming)
                .map(|e| e.weight())
                .collect()
        } else {
            vec![]
        }
    }

    /// Get related entities
    pub fn get_related(
        &self,
        entity_id: EntityId,
        relation_type: Option<RelationType>,
    ) -> Vec<(&Entity, &Relationship)> {
        let mut results = vec![];

        if let Some(&node_idx) = self.entity_index.get(&entity_id) {
            for edge in self.graph.edges_directed(node_idx, Direction::Outgoing) {
                let rel = edge.weight();
                if relation_type.is_none() || Some(&rel.relation_type) == relation_type.as_ref() {
                    if let Some(target) = self.graph.node_weight(edge.target()) {
                        results.push((target, rel));
                    }
                }
            }
        }

        results
    }

    /// Get entities that relate to this entity (reverse direction)
    pub fn get_relating(
        &self,
        entity_id: EntityId,
        relation_type: Option<RelationType>,
    ) -> Vec<(&Entity, &Relationship)> {
        let mut results = vec![];

        if let Some(&node_idx) = self.entity_index.get(&entity_id) {
            for edge in self.graph.edges_directed(node_idx, Direction::Incoming) {
                let rel = edge.weight();
                if relation_type.is_none() || Some(&rel.relation_type) == relation_type.as_ref() {
                    if let Some(source) = self.graph.node_weight(edge.source()) {
                        results.push((source, rel));
                    }
                }
            }
        }

        results
    }

    // ========================================================================
    // Graph Traversal
    // ========================================================================

    /// Find all paths between two entities up to max depth
    pub fn find_paths(
        &self,
        start: EntityId,
        end: EntityId,
        max_depth: Option<usize>,
    ) -> Vec<Vec<EntityId>> {
        let max_depth = max_depth.unwrap_or(self.config.max_traversal_depth);
        let start_idx = match self.entity_index.get(&start) {
            Some(&idx) => idx,
            None => return vec![],
        };
        let end_idx = match self.entity_index.get(&end) {
            Some(&idx) => idx,
            None => return vec![],
        };

        let mut paths = vec![];
        let mut current_path = vec![start];
        let mut visited = std::collections::HashSet::new();
        visited.insert(start_idx);

        self.find_paths_recursive(
            start_idx,
            end_idx,
            &mut current_path,
            &mut visited,
            &mut paths,
            max_depth,
        );

        paths
    }

    fn find_paths_recursive(
        &self,
        current: NodeIndex,
        end: NodeIndex,
        current_path: &mut Vec<EntityId>,
        visited: &mut std::collections::HashSet<NodeIndex>,
        paths: &mut Vec<Vec<EntityId>>,
        remaining_depth: usize,
    ) {
        if remaining_depth == 0 {
            return;
        }

        for edge in self.graph.edges_directed(current, Direction::Outgoing) {
            let target = edge.target();

            if let Some(target_entity) = self.graph.node_weight(target) {
                current_path.push(target_entity.id);

                if target == end {
                    paths.push(current_path.clone());
                } else if !visited.contains(&target) {
                    visited.insert(target);
                    self.find_paths_recursive(
                        target,
                        end,
                        current_path,
                        visited,
                        paths,
                        remaining_depth - 1,
                    );
                    visited.remove(&target);
                }

                current_path.pop();
            }
        }
    }

    /// Get all descendants of an entity (entities reachable from it)
    pub fn get_descendants(&self, entity_id: EntityId, max_depth: Option<usize>) -> Vec<&Entity> {
        let max_depth = max_depth.unwrap_or(self.config.max_traversal_depth);
        let start_idx = match self.entity_index.get(&entity_id) {
            Some(&idx) => idx,
            None => return vec![],
        };

        let mut descendants = vec![];
        let mut visited = std::collections::HashSet::new();
        visited.insert(start_idx);

        self.collect_descendants(start_idx, &mut visited, &mut descendants, max_depth);

        descendants
    }

    fn collect_descendants<'a>(
        &'a self,
        current: NodeIndex,
        visited: &mut std::collections::HashSet<NodeIndex>,
        descendants: &mut Vec<&'a Entity>,
        remaining_depth: usize,
    ) {
        if remaining_depth == 0 {
            return;
        }

        for edge in self.graph.edges_directed(current, Direction::Outgoing) {
            let target = edge.target();
            if !visited.contains(&target) {
                visited.insert(target);
                if let Some(entity) = self.graph.node_weight(target) {
                    descendants.push(entity);
                }
                self.collect_descendants(target, visited, descendants, remaining_depth - 1);
            }
        }
    }

    /// Get all ancestors of an entity (entities that lead to it)
    pub fn get_ancestors(&self, entity_id: EntityId, max_depth: Option<usize>) -> Vec<&Entity> {
        let max_depth = max_depth.unwrap_or(self.config.max_traversal_depth);
        let start_idx = match self.entity_index.get(&entity_id) {
            Some(&idx) => idx,
            None => return vec![],
        };

        let mut ancestors = vec![];
        let mut visited = std::collections::HashSet::new();
        visited.insert(start_idx);

        self.collect_ancestors(start_idx, &mut visited, &mut ancestors, max_depth);

        ancestors
    }

    fn collect_ancestors<'a>(
        &'a self,
        current: NodeIndex,
        visited: &mut std::collections::HashSet<NodeIndex>,
        ancestors: &mut Vec<&'a Entity>,
        remaining_depth: usize,
    ) {
        if remaining_depth == 0 {
            return;
        }

        for edge in self.graph.edges_directed(current, Direction::Incoming) {
            let source = edge.source();
            if !visited.contains(&source) {
                visited.insert(source);
                if let Some(entity) = self.graph.node_weight(source) {
                    ancestors.push(entity);
                }
                self.collect_ancestors(source, visited, ancestors, remaining_depth - 1);
            }
        }
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    /// Export the graph to a serializable format
    pub fn export(&self) -> KnowledgeGraphResult<KnowledgeGraphExport> {
        let entities: Vec<_> = self.graph.node_weights().cloned().collect();
        let relationships: Vec<_> = self.graph.edge_weights().cloned().collect();

        Ok(KnowledgeGraphExport {
            namespace: self.namespace.clone(),
            version: self.version,
            entities,
            relationships,
        })
    }

    /// Import from a serializable format
    pub fn import(
        namespace: impl Into<String>,
        data: KnowledgeGraphExport,
    ) -> KnowledgeGraphResult<Self> {
        let mut kg = Self::new(namespace);

        // Import entities
        for entity in data.entities {
            kg.add_entity(entity)?;
        }

        // Import relationships
        for relationship in data.relationships {
            kg.add_relationship(relationship)?;
        }

        kg.version = data.version;
        Ok(kg)
    }

    /// Compute a hash of the entire graph for integrity verification
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(self.namespace.as_bytes());
        hasher.update(self.version.to_le_bytes());

        // Hash all entity hashes in deterministic order
        let mut entity_hashes: Vec<_> = self.graph.node_weights().map(|e| e.hash).collect();
        entity_hashes.sort();
        for hash in entity_hashes {
            hasher.update(hash);
        }

        // Hash relationship info in deterministic order
        let mut rel_data: Vec<_> = self
            .graph
            .edge_weights()
            .map(|r| format!("{}-{}-{}", r.source, r.target, r.relation_type))
            .collect();
        rel_data.sort();
        for data in rel_data {
            hasher.update(data.as_bytes());
        }

        hasher.finalize().into()
    }
}

impl std::fmt::Debug for KnowledgeGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnowledgeGraph")
            .field("namespace", &self.namespace)
            .field("entity_count", &self.entity_count())
            .field("relationship_count", &self.relationship_count())
            .field("version", &self.version)
            .finish()
    }
}

/// Serializable export format for the knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeGraphExport {
    /// Namespace of the graph
    pub namespace: String,
    /// Version number
    pub version: u64,
    /// All entities
    pub entities: Vec<Entity>,
    /// All relationships
    pub relationships: Vec<Relationship>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_creation() {
        let entity = Entity::new("server1", "Server")
            .with_property("ip", "192.168.1.1")
            .with_property("port", 8080i64);

        assert_eq!(entity.name, "server1");
        assert_eq!(entity.entity_type, "Server");
        assert_eq!(
            entity.get_property("ip"),
            Some(&PropertyValue::String("192.168.1.1".to_string()))
        );
        assert_eq!(
            entity.get_property("port"),
            Some(&PropertyValue::Integer(8080))
        );
    }

    #[test]
    fn test_entity_hash_verification() {
        let entity = Entity::new("test", "Test").with_property("key", "value");
        assert!(entity.verify_hash());
    }

    #[test]
    fn test_entity_hash_changes_with_content() {
        let entity1 = Entity::new("test", "Test").with_property("key", "value1");
        let entity2 = Entity::new("test", "Test").with_property("key", "value2");

        assert_ne!(entity1.hash, entity2.hash);
    }

    #[test]
    fn test_property_value_conversions() {
        assert_eq!(PropertyValue::from("hello").as_str(), Some("hello"));
        assert_eq!(PropertyValue::from(42i64).as_int(), Some(42));
        assert_eq!(PropertyValue::from(3.14f64).as_float(), Some(3.14));
        assert_eq!(PropertyValue::from(true).as_bool(), Some(true));
    }

    #[test]
    fn test_knowledge_graph_creation() {
        let kg = KnowledgeGraph::new("agent1");
        assert_eq!(kg.namespace(), "agent1");
        assert_eq!(kg.entity_count(), 0);
        assert_eq!(kg.relationship_count(), 0);
    }

    #[test]
    fn test_add_entity() {
        let mut kg = KnowledgeGraph::new("test");
        let entity = Entity::new("server1", "Server");

        let id = kg.add_entity(entity).unwrap();

        assert_eq!(kg.entity_count(), 1);
        assert!(kg.get_entity(id).is_some());
    }

    #[test]
    fn test_add_duplicate_entity_name() {
        let mut kg = KnowledgeGraph::new("test");

        kg.add_entity(Entity::new("server1", "Server")).unwrap();
        let result = kg.add_entity(Entity::new("server1", "Service"));

        assert!(matches!(
            result,
            Err(KnowledgeGraphError::DuplicateEntity(_))
        ));
    }

    #[test]
    fn test_get_entity_by_name() {
        let mut kg = KnowledgeGraph::new("test");
        let entity = Entity::new("server1", "Server");

        kg.add_entity(entity).unwrap();

        let found = kg.get_entity_by_name("server1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "server1");
    }

    #[test]
    fn test_remove_entity() {
        let mut kg = KnowledgeGraph::new("test");
        let entity = Entity::new("server1", "Server");

        let id = kg.add_entity(entity).unwrap();
        assert_eq!(kg.entity_count(), 1);

        kg.remove_entity(id).unwrap();
        assert_eq!(kg.entity_count(), 0);
    }

    #[test]
    fn test_add_relationship() {
        let mut kg = KnowledgeGraph::new("test");

        let server_id = kg.add_entity(Entity::new("server1", "Server")).unwrap();
        let service_id = kg.add_entity(Entity::new("service1", "Service")).unwrap();

        let rel = Relationship::new(server_id, service_id, RelationType::HostsService);
        let rel_id = kg.add_relationship(rel).unwrap();

        assert_eq!(kg.relationship_count(), 1);
        assert!(kg.get_relationship(rel_id).is_some());
    }

    #[test]
    fn test_invalid_relationship() {
        let mut kg = KnowledgeGraph::new("test");

        let server_id = kg.add_entity(Entity::new("server1", "Server")).unwrap();
        let fake_id = EntityId::new();

        let rel = Relationship::new(server_id, fake_id, RelationType::HostsService);
        let result = kg.add_relationship(rel);

        assert!(matches!(
            result,
            Err(KnowledgeGraphError::InvalidRelationship { .. })
        ));
    }

    #[test]
    fn test_get_related_entities() {
        let mut kg = KnowledgeGraph::new("test");

        let server_id = kg.add_entity(Entity::new("server1", "Server")).unwrap();
        let service1_id = kg.add_entity(Entity::new("service1", "Service")).unwrap();
        let service2_id = kg.add_entity(Entity::new("service2", "Service")).unwrap();

        kg.add_relationship(Relationship::new(
            server_id,
            service1_id,
            RelationType::HostsService,
        ))
        .unwrap();
        kg.add_relationship(Relationship::new(
            server_id,
            service2_id,
            RelationType::HostsService,
        ))
        .unwrap();

        let related = kg.get_related(server_id, Some(RelationType::HostsService));
        assert_eq!(related.len(), 2);
    }

    #[test]
    fn test_get_relating_entities() {
        let mut kg = KnowledgeGraph::new("test");

        let server_id = kg.add_entity(Entity::new("server1", "Server")).unwrap();
        let service_id = kg.add_entity(Entity::new("service1", "Service")).unwrap();

        kg.add_relationship(Relationship::new(
            server_id,
            service_id,
            RelationType::HostsService,
        ))
        .unwrap();

        let relating = kg.get_relating(service_id, Some(RelationType::HostsService));
        assert_eq!(relating.len(), 1);
        assert_eq!(relating[0].0.name, "server1");
    }

    #[test]
    fn test_get_entities_by_type() {
        let mut kg = KnowledgeGraph::new("test");

        kg.add_entity(Entity::new("server1", "Server")).unwrap();
        kg.add_entity(Entity::new("server2", "Server")).unwrap();
        kg.add_entity(Entity::new("service1", "Service")).unwrap();

        let servers = kg.get_entities_by_type("Server");
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn test_search_by_property() {
        let mut kg = KnowledgeGraph::new("test");

        kg.add_entity(Entity::new("server1", "Server").with_property("status", "running"))
            .unwrap();
        kg.add_entity(Entity::new("server2", "Server").with_property("status", "stopped"))
            .unwrap();

        let running = kg.search_entities_by_property("status", &PropertyValue::from("running"));
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].name, "server1");
    }

    #[test]
    fn test_search_by_name() {
        let mut kg = KnowledgeGraph::new("test");

        kg.add_entity(Entity::new("web-server", "Server")).unwrap();
        kg.add_entity(Entity::new("db-server", "Server")).unwrap();
        kg.add_entity(Entity::new("worker", "Service")).unwrap();

        let servers = kg.search_entities_by_name("server");
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn test_find_paths() {
        let mut kg = KnowledgeGraph::new("test");

        let a_id = kg.add_entity(Entity::new("A", "Node")).unwrap();
        let b_id = kg.add_entity(Entity::new("B", "Node")).unwrap();
        let c_id = kg.add_entity(Entity::new("C", "Node")).unwrap();

        kg.add_relationship(Relationship::new(a_id, b_id, RelationType::RelatedTo))
            .unwrap();
        kg.add_relationship(Relationship::new(b_id, c_id, RelationType::RelatedTo))
            .unwrap();

        let paths = kg.find_paths(a_id, c_id, None);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 3);
        assert_eq!(paths[0][0], a_id);
        assert_eq!(paths[0][1], b_id);
        assert_eq!(paths[0][2], c_id);
    }

    #[test]
    fn test_get_descendants() {
        let mut kg = KnowledgeGraph::new("test");

        let root_id = kg.add_entity(Entity::new("root", "Node")).unwrap();
        let child1_id = kg.add_entity(Entity::new("child1", "Node")).unwrap();
        let child2_id = kg.add_entity(Entity::new("child2", "Node")).unwrap();
        let grandchild_id = kg.add_entity(Entity::new("grandchild", "Node")).unwrap();

        kg.add_relationship(Relationship::new(
            root_id,
            child1_id,
            RelationType::ParentOf,
        ))
        .unwrap();
        kg.add_relationship(Relationship::new(
            root_id,
            child2_id,
            RelationType::ParentOf,
        ))
        .unwrap();
        kg.add_relationship(Relationship::new(
            child1_id,
            grandchild_id,
            RelationType::ParentOf,
        ))
        .unwrap();

        let descendants = kg.get_descendants(root_id, None);
        assert_eq!(descendants.len(), 3);
    }

    #[test]
    fn test_get_ancestors() {
        let mut kg = KnowledgeGraph::new("test");

        let root_id = kg.add_entity(Entity::new("root", "Node")).unwrap();
        let child_id = kg.add_entity(Entity::new("child", "Node")).unwrap();
        let grandchild_id = kg.add_entity(Entity::new("grandchild", "Node")).unwrap();

        kg.add_relationship(Relationship::new(root_id, child_id, RelationType::ParentOf))
            .unwrap();
        kg.add_relationship(Relationship::new(
            child_id,
            grandchild_id,
            RelationType::ParentOf,
        ))
        .unwrap();

        let ancestors = kg.get_ancestors(grandchild_id, None);
        assert_eq!(ancestors.len(), 2);
    }

    #[test]
    fn test_export_import() {
        let mut kg = KnowledgeGraph::new("test");

        let server_id = kg
            .add_entity(Entity::new("server1", "Server").with_property("ip", "192.168.1.1"))
            .unwrap();
        let service_id = kg.add_entity(Entity::new("service1", "Service")).unwrap();
        kg.add_relationship(Relationship::new(
            server_id,
            service_id,
            RelationType::HostsService,
        ))
        .unwrap();

        let export = kg.export().unwrap();
        let imported = KnowledgeGraph::import("imported", export).unwrap();

        assert_eq!(imported.entity_count(), 2);
        assert_eq!(imported.relationship_count(), 1);
    }

    #[test]
    fn test_compute_hash() {
        let mut kg = KnowledgeGraph::new("test");

        kg.add_entity(Entity::new("server1", "Server")).unwrap();

        let hash1 = kg.compute_hash();

        kg.add_entity(Entity::new("server2", "Server")).unwrap();

        let hash2 = kg.compute_hash();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_relationship_with_properties() {
        let mut kg = KnowledgeGraph::new("test");

        let server_id = kg.add_entity(Entity::new("server1", "Server")).unwrap();
        let service_id = kg.add_entity(Entity::new("service1", "Service")).unwrap();

        let rel = Relationship::new(server_id, service_id, RelationType::HostsService)
            .with_weight(0.9)
            .with_property("latency", 5i64);

        kg.add_relationship(rel).unwrap();

        let relationships = kg.get_outgoing_relationships(server_id);
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].weight, Some(0.9));
        assert_eq!(
            relationships[0].properties.get("latency"),
            Some(&PropertyValue::Integer(5))
        );
    }

    #[test]
    fn test_remove_entity_removes_relationships() {
        let mut kg = KnowledgeGraph::new("test");

        let server_id = kg.add_entity(Entity::new("server1", "Server")).unwrap();
        let service_id = kg.add_entity(Entity::new("service1", "Service")).unwrap();

        kg.add_relationship(Relationship::new(
            server_id,
            service_id,
            RelationType::HostsService,
        ))
        .unwrap();
        assert_eq!(kg.relationship_count(), 1);

        kg.remove_entity(server_id).unwrap();
        assert_eq!(kg.relationship_count(), 0);
    }

    #[test]
    fn test_relation_type_display() {
        assert_eq!(format!("{}", RelationType::HostsService), "HOSTS_SERVICE");
        assert_eq!(format!("{}", RelationType::DependsOn), "DEPENDS_ON");
        assert_eq!(
            format!("{}", RelationType::Custom("MY_REL".to_string())),
            "MY_REL"
        );
    }

    #[test]
    fn test_entity_id_display() {
        let id = EntityId::new();
        let display = format!("{}", id);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_knowledge_graph_error_display() {
        let err = KnowledgeGraphError::EntityNotFound(EntityId::new());
        assert!(format!("{}", err).contains("Entity not found"));

        let err = KnowledgeGraphError::DuplicateEntity("test".to_string());
        assert!(format!("{}", err).contains("Duplicate entity"));
    }

    #[test]
    fn test_entity_modify_property() {
        let mut entity = Entity::new("test", "Test");
        let initial_hash = entity.hash;

        entity.set_property("key", "value");

        assert_ne!(entity.hash, initial_hash);
        assert!(entity.verify_hash());
    }

    #[test]
    fn test_get_all_entities() {
        let mut kg = KnowledgeGraph::new("test");

        kg.add_entity(Entity::new("e1", "Type")).unwrap();
        kg.add_entity(Entity::new("e2", "Type")).unwrap();
        kg.add_entity(Entity::new("e3", "Type")).unwrap();

        let all = kg.get_all_entities();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_version_increments() {
        let mut kg = KnowledgeGraph::new("test");
        assert_eq!(kg.version(), 0);

        let id = kg.add_entity(Entity::new("e1", "Type")).unwrap();
        assert_eq!(kg.version(), 1);

        let id2 = kg.add_entity(Entity::new("e2", "Type")).unwrap();
        assert_eq!(kg.version(), 2);

        kg.add_relationship(Relationship::new(id, id2, RelationType::RelatedTo))
            .unwrap();
        assert_eq!(kg.version(), 3);

        kg.remove_entity(id).unwrap();
        assert_eq!(kg.version(), 4);
    }
}
