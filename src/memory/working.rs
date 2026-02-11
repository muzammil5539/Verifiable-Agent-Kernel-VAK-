//! Working Memory with Dynamic Summarization (MEM-002)
//!
//! This module provides a working memory system that maintains the current
//! context window with automatic summarization when it exceeds capacity.
//! Following the CoALA framework, working memory is the "hot" tier that
//! interfaces directly with the LLM's context window.
//!
//! # Features
//! - **Dynamic summarization**: Automatically summarizes old content when capacity is exceeded
//! - **Priority-based retention**: Important items are retained longer
//! - **Token tracking**: Estimates token usage to manage context window effectively
//! - **LLM integration**: Uses LLM for intelligent summarization
//!
//! # Example
//! ```rust,no_run
//! use vak::memory::working::{WorkingMemory, WorkingMemoryConfig, MemoryItem};
//! use vak::llm::{LiteLlmClient, LlmConfig, MockLlmProvider};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Use mock provider for example
//!     let llm = Arc::new(MockLlmProvider::new());
//!     let config = WorkingMemoryConfig::default();
//!     let mut memory = WorkingMemory::new(llm, config);
//!     
//!     // Add items to working memory
//!     memory.add_item(MemoryItem::user_message("What is the capital of France?"));
//!     memory.add_item(MemoryItem::assistant_message("The capital of France is Paris."));
//!     
//!     // Get context for LLM
//!     let context = memory.get_context();
//!     println!("Context has {} items", context.len());
//!     
//!     Ok(())
//! }
//! ```

use crate::llm::{CompletionRequest, LlmError, LlmProvider, Message, Role};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for working memory behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingMemoryConfig {
    /// Maximum number of tokens before triggering summarization
    pub max_tokens: usize,

    /// Target token count after summarization
    pub target_tokens_after_summarization: usize,

    /// Number of recent items to always keep (not summarized)
    pub protected_recent_items: usize,

    /// Model to use for summarization
    pub summarization_model: String,

    /// Temperature for summarization (lower = more deterministic)
    pub summarization_temperature: f32,

    /// Maximum tokens for summarization response
    pub summarization_max_tokens: usize,

    /// Whether to include timestamps in summaries
    pub include_timestamps_in_summary: bool,

    /// Minimum items before allowing summarization
    pub min_items_for_summarization: usize,

    /// Average characters per token (for estimation)
    pub chars_per_token_estimate: f32,
}

impl Default for WorkingMemoryConfig {
    fn default() -> Self {
        Self {
            max_tokens: 4096,
            target_tokens_after_summarization: 2048,
            protected_recent_items: 3,
            summarization_model: "gpt-3.5-turbo".to_string(),
            summarization_temperature: 0.3,
            summarization_max_tokens: 1024,
            include_timestamps_in_summary: false,
            min_items_for_summarization: 5,
            chars_per_token_estimate: 4.0, // Rough estimate for English text
        }
    }
}

impl WorkingMemoryConfig {
    /// Create a new configuration with custom max tokens
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = max_tokens;
        self.target_tokens_after_summarization = max_tokens / 2;
        self
    }

    /// Set the summarization model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.summarization_model = model.into();
        self
    }

    /// Set the number of protected recent items
    pub fn with_protected_recent(mut self, count: usize) -> Self {
        self.protected_recent_items = count;
        self
    }
}

// ============================================================================
// Memory Item Types
// ============================================================================

/// Priority level for memory items
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[derive(Default)]
pub enum ItemPriority {
    /// Low priority - can be summarized early
    Low = 0,
    /// Normal priority - default for most items
    #[default]
    Normal = 1,
    /// High priority - retained longer before summarization
    High = 2,
    /// Critical - never automatically summarized
    Critical = 3,
}


/// Type of memory item
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemType {
    /// System instruction
    System,
    /// User message/input
    UserMessage,
    /// Assistant response
    AssistantMessage,
    /// Tool/function call
    ToolCall {
        /// Name of the tool being called
        tool_name: String,
    },
    /// Tool/function result
    ToolResult {
        /// Name of the tool that produced the result
        tool_name: String,
    },
    /// Observation from the environment
    Observation,
    /// Agent's internal thought/reasoning
    Thought,
    /// Summary of previous items
    Summary {
        /// Number of items that were summarized
        items_summarized: usize,
        /// Time range covered by the summary
        time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    },
    /// Custom item type
    Custom(String),
}

/// A single item in working memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryItem {
    /// Unique identifier for this item
    pub id: Uuid,

    /// Type of the item
    pub item_type: ItemType,

    /// The content of the item
    pub content: String,

    /// When this item was created
    pub timestamp: DateTime<Utc>,

    /// Priority level for retention
    pub priority: ItemPriority,

    /// Estimated token count
    pub estimated_tokens: usize,

    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
}

impl MemoryItem {
    /// Create a new memory item
    pub fn new(item_type: ItemType, content: impl Into<String>) -> Self {
        let content = content.into();
        let estimated_tokens = estimate_tokens(&content);
        Self {
            id: Uuid::now_v7(),
            item_type,
            content,
            timestamp: Utc::now(),
            priority: ItemPriority::default(),
            estimated_tokens,
            metadata: None,
        }
    }

    /// Create a system message
    pub fn system(content: impl Into<String>) -> Self {
        Self::new(ItemType::System, content).with_priority(ItemPriority::Critical)
    }

    /// Create a user message
    pub fn user_message(content: impl Into<String>) -> Self {
        Self::new(ItemType::UserMessage, content)
    }

    /// Create an assistant message
    pub fn assistant_message(content: impl Into<String>) -> Self {
        Self::new(ItemType::AssistantMessage, content)
    }

    /// Create a tool call item
    pub fn tool_call(tool_name: impl Into<String>, content: impl Into<String>) -> Self {
        Self::new(
            ItemType::ToolCall {
                tool_name: tool_name.into(),
            },
            content,
        )
    }

    /// Create a tool result item
    pub fn tool_result(tool_name: impl Into<String>, content: impl Into<String>) -> Self {
        Self::new(
            ItemType::ToolResult {
                tool_name: tool_name.into(),
            },
            content,
        )
    }

    /// Create an observation item
    pub fn observation(content: impl Into<String>) -> Self {
        Self::new(ItemType::Observation, content)
    }

    /// Create a thought item
    pub fn thought(content: impl Into<String>) -> Self {
        Self::new(ItemType::Thought, content)
    }

    /// Create a summary item
    pub fn summary(content: impl Into<String>, items_summarized: usize) -> Self {
        Self::new(
            ItemType::Summary {
                items_summarized,
                time_range: None,
            },
            content,
        )
        .with_priority(ItemPriority::High)
    }

    /// Create a summary with time range
    pub fn summary_with_range(
        content: impl Into<String>,
        items_summarized: usize,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Self {
        Self::new(
            ItemType::Summary {
                items_summarized,
                time_range: Some((start, end)),
            },
            content,
        )
        .with_priority(ItemPriority::High)
    }

    /// Set the priority
    pub fn with_priority(mut self, priority: ItemPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Convert to an LLM message
    pub fn to_message(&self) -> Message {
        match &self.item_type {
            ItemType::System => Message::system(&self.content),
            ItemType::UserMessage => Message::user(&self.content),
            ItemType::AssistantMessage => Message::assistant(&self.content),
            ItemType::ToolCall { tool_name } => Message::function(tool_name.clone(), &self.content),
            ItemType::ToolResult { tool_name } => {
                Message::function(tool_name.clone(), &self.content)
            }
            ItemType::Observation => Message::user(format!("[Observation] {}", self.content)),
            ItemType::Thought => Message::assistant(format!("[Thought] {}", self.content)),
            ItemType::Summary { .. } => Message::system(format!(
                "[Summary of previous conversation]\n{}",
                self.content
            )),
            ItemType::Custom(type_name) => {
                Message::user(format!("[{}] {}", type_name, self.content))
            }
        }
    }

    /// Get the role for this item type
    pub fn role(&self) -> Role {
        match &self.item_type {
            ItemType::System => Role::System,
            ItemType::UserMessage => Role::User,
            ItemType::AssistantMessage => Role::Assistant,
            ItemType::ToolCall { .. } => Role::Function,
            ItemType::ToolResult { .. } => Role::Function,
            ItemType::Observation => Role::User,
            ItemType::Thought => Role::Assistant,
            ItemType::Summary { .. } => Role::System,
            ItemType::Custom(_) => Role::User,
        }
    }
}

/// Estimate token count from content using content-aware heuristics (Issue #15)
///
/// Uses different ratios for different content types:
/// - Code: ~3.5 chars/token (more symbols, shorter tokens)
/// - Non-ASCII/CJK: ~1.5 chars/token (multi-byte characters)
/// - Whitespace-heavy: accounts for whitespace tokens
/// - Standard English: ~4 chars/token
fn estimate_tokens(content: &str) -> usize {
    if content.is_empty() {
        return 0;
    }

    let _total_chars = content.len();
    let mut code_chars = 0usize;
    let mut non_ascii_chars = 0usize;
    let mut whitespace_chars = 0usize;
    let mut normal_chars = 0usize;

    for ch in content.chars() {
        if !ch.is_ascii() {
            non_ascii_chars += ch.len_utf8();
        } else if ch.is_ascii_whitespace() {
            whitespace_chars += 1;
        } else if "{}[]()<>|&;=!@#$%^*+-/\\~`'\",:._".contains(ch) {
            code_chars += 1;
        } else {
            normal_chars += 1;
        }
    }

    // Calculate weighted token estimate
    // Non-ASCII (CJK, emoji, etc.): ~1.5 bytes per token
    let non_ascii_tokens = (non_ascii_chars as f32 / 1.5).ceil() as usize;
    // Code/symbols: ~3.5 chars per token (symbols tokenize individually more often)
    let code_tokens = (code_chars as f32 / 3.5).ceil() as usize;
    // Whitespace: roughly 1 token per whitespace run, approximate as 1 per 2 whitespace chars
    let whitespace_tokens = (whitespace_chars as f32 / 2.0).ceil() as usize;
    // Normal text: ~4 chars per token
    let normal_tokens = (normal_chars as f32 / 4.0).ceil() as usize;

    let estimated = non_ascii_tokens + code_tokens + whitespace_tokens + normal_tokens;

    // Never return 0 for non-empty content
    std::cmp::max(1, estimated)
}

// ============================================================================
// Working Memory Errors
// ============================================================================

/// Errors that can occur in working memory operations
#[derive(Debug, Clone)]
pub enum WorkingMemoryError {
    /// LLM error during summarization
    LlmError(String),
    /// Configuration error
    ConfigError(String),
    /// Memory is empty when it shouldn't be
    EmptyMemory,
    /// Item not found
    ItemNotFound(Uuid),
}

impl std::fmt::Display for WorkingMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkingMemoryError::LlmError(msg) => write!(f, "LLM error: {}", msg),
            WorkingMemoryError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            WorkingMemoryError::EmptyMemory => write!(f, "Working memory is empty"),
            WorkingMemoryError::ItemNotFound(id) => write!(f, "Item not found: {}", id),
        }
    }
}

impl std::error::Error for WorkingMemoryError {}

impl From<LlmError> for WorkingMemoryError {
    fn from(error: LlmError) -> Self {
        WorkingMemoryError::LlmError(error.to_string())
    }
}

// ============================================================================
// Working Memory
// ============================================================================

/// Working Memory with Dynamic Summarization
///
/// Maintains the current context window and automatically summarizes
/// older content when the token limit is exceeded.
pub struct WorkingMemory<P: LlmProvider> {
    /// Items in working memory
    items: VecDeque<MemoryItem>,

    /// LLM provider for summarization
    llm: Arc<P>,

    /// Configuration
    config: WorkingMemoryConfig,

    /// Current estimated token count
    current_tokens: usize,

    /// Number of times summarization has been performed
    summarization_count: usize,
}

impl<P: LlmProvider> WorkingMemory<P> {
    /// Create a new working memory instance
    pub fn new(llm: Arc<P>, config: WorkingMemoryConfig) -> Self {
        Self {
            items: VecDeque::new(),
            llm,
            config,
            current_tokens: 0,
            summarization_count: 0,
        }
    }

    /// Create with default configuration
    pub fn with_defaults(llm: Arc<P>) -> Self {
        Self::new(llm, WorkingMemoryConfig::default())
    }

    /// Get the current configuration
    pub fn config(&self) -> &WorkingMemoryConfig {
        &self.config
    }

    /// Get the current estimated token count
    pub fn current_tokens(&self) -> usize {
        self.current_tokens
    }

    /// Get the number of items in working memory
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if working memory is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get the number of times summarization has been performed
    pub fn summarization_count(&self) -> usize {
        self.summarization_count
    }

    /// Add an item to working memory
    pub fn add_item(&mut self, item: MemoryItem) {
        self.current_tokens += item.estimated_tokens;
        self.items.push_back(item);
    }

    /// Add multiple items to working memory
    pub fn add_items(&mut self, items: impl IntoIterator<Item = MemoryItem>) {
        for item in items {
            self.add_item(item);
        }
    }

    /// Check if summarization is needed
    pub fn needs_summarization(&self) -> bool {
        self.current_tokens > self.config.max_tokens
            && self.items.len() >= self.config.min_items_for_summarization
    }

    /// Get items that can be summarized (excluding protected recent items)
    fn get_summarizable_items(&self) -> Vec<&MemoryItem> {
        let protected_count = self.config.protected_recent_items.min(self.items.len());
        let summarizable_end = self.items.len().saturating_sub(protected_count);

        self.items
            .iter()
            .take(summarizable_end)
            .filter(|item| item.priority < ItemPriority::Critical)
            .collect()
    }

    /// Perform summarization to reduce token count
    pub async fn summarize(&mut self) -> Result<(), WorkingMemoryError> {
        if !self.needs_summarization() {
            return Ok(());
        }

        let summarizable = self.get_summarizable_items();
        if summarizable.is_empty() {
            return Ok(());
        }

        // Calculate how many items to summarize
        let tokens_to_remove = self.current_tokens - self.config.target_tokens_after_summarization;
        let mut items_to_summarize = Vec::new();
        let mut removed_tokens = 0;

        for item in &summarizable {
            if removed_tokens >= tokens_to_remove {
                break;
            }
            items_to_summarize.push(*item);
            removed_tokens += item.estimated_tokens;
        }

        if items_to_summarize.is_empty() {
            return Ok(());
        }

        // Build the content to summarize
        let content_to_summarize = items_to_summarize
            .iter()
            .map(|item| {
                let timestamp = if self.config.include_timestamps_in_summary {
                    format!("[{}] ", item.timestamp.format("%H:%M:%S"))
                } else {
                    String::new()
                };
                format!(
                    "{}{}: {}",
                    timestamp,
                    format_item_type(&item.item_type),
                    item.content
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Generate summary using LLM
        let summary_content = self.generate_summary(&content_to_summarize).await?;

        // Get time range
        let time_range = if items_to_summarize.len() >= 2 {
            Some((
                items_to_summarize.first().unwrap().timestamp,
                items_to_summarize.last().unwrap().timestamp,
            ))
        } else {
            None
        };

        // Create summary item
        let summary_item = if let Some((start, end)) = time_range {
            MemoryItem::summary_with_range(&summary_content, items_to_summarize.len(), start, end)
        } else {
            MemoryItem::summary(&summary_content, items_to_summarize.len())
        };

        // Remove summarized items
        let items_to_remove: std::collections::HashSet<_> =
            items_to_summarize.iter().map(|i| i.id).collect();
        let mut new_items = VecDeque::new();
        let mut new_tokens = 0;

        // Add the summary first
        new_tokens += summary_item.estimated_tokens;
        new_items.push_back(summary_item);

        // Keep items that weren't summarized
        for item in self.items.drain(..) {
            if !items_to_remove.contains(&item.id) {
                new_tokens += item.estimated_tokens;
                new_items.push_back(item);
            }
        }

        self.items = new_items;
        self.current_tokens = new_tokens;
        self.summarization_count += 1;

        Ok(())
    }

    /// Generate a summary using the LLM
    async fn generate_summary(&self, content: &str) -> Result<String, WorkingMemoryError> {
        let system_prompt = r#"You are a summarization assistant. Summarize the following conversation history concisely while preserving:
1. Key decisions made
2. Important information exchanged
3. Pending tasks or questions
4. Context necessary for continuing the conversation

Be concise but complete. Focus on information that would be needed to continue the conversation meaningfully."#;

        let request = CompletionRequest::new(&self.config.summarization_model)
            .with_message(Message::system(system_prompt))
            .with_message(Message::user(format!(
                "Summarize the following conversation history:\n\n{}",
                content
            )))
            .with_temperature(self.config.summarization_temperature)
            .with_max_tokens(self.config.summarization_max_tokens);

        let response = self.llm.complete(request).await?;
        Ok(response.content)
    }

    /// Get the current context as messages for LLM
    pub fn get_context(&self) -> Vec<Message> {
        self.items.iter().map(|item| item.to_message()).collect()
    }

    /// Get all items in working memory
    pub fn get_items(&self) -> &VecDeque<MemoryItem> {
        &self.items
    }

    /// Get an item by ID
    pub fn get_item(&self, id: &Uuid) -> Option<&MemoryItem> {
        self.items.iter().find(|item| &item.id == id)
    }

    /// Remove an item by ID
    pub fn remove_item(&mut self, id: &Uuid) -> Option<MemoryItem> {
        if let Some(pos) = self.items.iter().position(|item| &item.id == id) {
            let item = self.items.remove(pos)?;
            self.current_tokens = self.current_tokens.saturating_sub(item.estimated_tokens);
            Some(item)
        } else {
            None
        }
    }

    /// Clear all items except system messages
    pub fn clear_except_system(&mut self) {
        let system_items: VecDeque<_> = self
            .items
            .drain(..)
            .filter(|item| matches!(item.item_type, ItemType::System))
            .collect();

        self.current_tokens = system_items.iter().map(|i| i.estimated_tokens).sum();
        self.items = system_items;
    }

    /// Clear all items
    pub fn clear(&mut self) {
        self.items.clear();
        self.current_tokens = 0;
    }

    /// Get items by type
    pub fn get_items_by_type(&self, item_type: &ItemType) -> Vec<&MemoryItem> {
        self.items
            .iter()
            .filter(|item| {
                std::mem::discriminant(&item.item_type) == std::mem::discriminant(item_type)
            })
            .collect()
    }

    /// Get the most recent N items
    pub fn get_recent(&self, n: usize) -> Vec<&MemoryItem> {
        self.items.iter().rev().take(n).collect()
    }

    /// Search items by content
    pub fn search(&self, query: &str) -> Vec<&MemoryItem> {
        let query_lower = query.to_lowercase();
        self.items
            .iter()
            .filter(|item| item.content.to_lowercase().contains(&query_lower))
            .collect()
    }

    /// Recalculate token count (useful after manual modifications)
    pub fn recalculate_tokens(&mut self) {
        self.current_tokens = self.items.iter().map(|i| i.estimated_tokens).sum();
    }

    /// Export working memory to JSON
    pub fn export(&self) -> Result<String, WorkingMemoryError> {
        let items: Vec<_> = self.items.iter().collect();
        serde_json::to_string_pretty(&items)
            .map_err(|e| WorkingMemoryError::ConfigError(e.to_string()))
    }

    /// Import items from JSON (appends to existing items)
    pub fn import(&mut self, json: &str) -> Result<usize, WorkingMemoryError> {
        let items: Vec<MemoryItem> = serde_json::from_str(json)
            .map_err(|e| WorkingMemoryError::ConfigError(e.to_string()))?;
        let count = items.len();
        self.add_items(items);
        Ok(count)
    }
}

/// Format an item type for display
fn format_item_type(item_type: &ItemType) -> &'static str {
    match item_type {
        ItemType::System => "System",
        ItemType::UserMessage => "User",
        ItemType::AssistantMessage => "Assistant",
        ItemType::ToolCall { .. } => "ToolCall",
        ItemType::ToolResult { .. } => "ToolResult",
        ItemType::Observation => "Observation",
        ItemType::Thought => "Thought",
        ItemType::Summary { .. } => "Summary",
        ItemType::Custom(_) => "Custom",
    }
}

impl<P: LlmProvider> std::fmt::Debug for WorkingMemory<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkingMemory")
            .field("items_count", &self.items.len())
            .field("current_tokens", &self.current_tokens)
            .field("summarization_count", &self.summarization_count)
            .field("config", &self.config)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::MockLlmProvider;

    fn create_test_memory() -> WorkingMemory<MockLlmProvider> {
        let llm = Arc::new(MockLlmProvider::new());
        WorkingMemory::new(llm, WorkingMemoryConfig::default())
    }

    #[test]
    fn test_working_memory_creation() {
        let memory = create_test_memory();
        assert!(memory.is_empty());
        assert_eq!(memory.current_tokens(), 0);
        assert_eq!(memory.summarization_count(), 0);
    }

    #[test]
    fn test_add_item() {
        let mut memory = create_test_memory();

        memory.add_item(MemoryItem::user_message("Hello, world!"));

        assert_eq!(memory.len(), 1);
        assert!(!memory.is_empty());
        assert!(memory.current_tokens() > 0);
    }

    #[test]
    fn test_add_multiple_items() {
        let mut memory = create_test_memory();

        memory.add_items(vec![
            MemoryItem::system("You are a helpful assistant."),
            MemoryItem::user_message("Hello!"),
            MemoryItem::assistant_message("Hi there!"),
        ]);

        assert_eq!(memory.len(), 3);
    }

    #[test]
    fn test_memory_item_creation() {
        let system = MemoryItem::system("System prompt");
        assert!(matches!(system.item_type, ItemType::System));
        assert_eq!(system.priority, ItemPriority::Critical);

        let user = MemoryItem::user_message("User input");
        assert!(matches!(user.item_type, ItemType::UserMessage));
        assert_eq!(user.priority, ItemPriority::Normal);

        let assistant = MemoryItem::assistant_message("Response");
        assert!(matches!(assistant.item_type, ItemType::AssistantMessage));

        let tool_call = MemoryItem::tool_call("calculator", r#"{"op": "add"}"#);
        assert!(matches!(tool_call.item_type, ItemType::ToolCall { .. }));

        let tool_result = MemoryItem::tool_result("calculator", "42");
        assert!(matches!(tool_result.item_type, ItemType::ToolResult { .. }));

        let observation = MemoryItem::observation("Environment changed");
        assert!(matches!(observation.item_type, ItemType::Observation));

        let thought = MemoryItem::thought("I should analyze this");
        assert!(matches!(thought.item_type, ItemType::Thought));
    }

    #[test]
    fn test_item_to_message() {
        let system = MemoryItem::system("Be helpful");
        let msg = system.to_message();
        assert_eq!(msg.role, Role::System);
        assert_eq!(msg.content, "Be helpful");

        let user = MemoryItem::user_message("Question");
        let msg = user.to_message();
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.content, "Question");
    }

    #[test]
    fn test_get_context() {
        let mut memory = create_test_memory();

        memory.add_items(vec![
            MemoryItem::system("System"),
            MemoryItem::user_message("User"),
            MemoryItem::assistant_message("Assistant"),
        ]);

        let context = memory.get_context();
        assert_eq!(context.len(), 3);
        assert_eq!(context[0].role, Role::System);
        assert_eq!(context[1].role, Role::User);
        assert_eq!(context[2].role, Role::Assistant);
    }

    #[test]
    fn test_get_item_by_id() {
        let mut memory = create_test_memory();

        let item = MemoryItem::user_message("Test");
        let id = item.id;
        memory.add_item(item);

        let found = memory.get_item(&id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().content, "Test");

        let not_found = memory.get_item(&Uuid::new_v4());
        assert!(not_found.is_none());
    }

    #[test]
    fn test_remove_item() {
        let mut memory = create_test_memory();

        let item = MemoryItem::user_message("Test");
        let id = item.id;
        let tokens = item.estimated_tokens;
        memory.add_item(item);

        assert_eq!(memory.len(), 1);
        let initial_tokens = memory.current_tokens();

        let removed = memory.remove_item(&id);
        assert!(removed.is_some());
        assert_eq!(memory.len(), 0);
        assert_eq!(memory.current_tokens(), initial_tokens - tokens);
    }

    #[test]
    fn test_clear() {
        let mut memory = create_test_memory();

        memory.add_items(vec![
            MemoryItem::system("System"),
            MemoryItem::user_message("User"),
        ]);

        memory.clear();
        assert!(memory.is_empty());
        assert_eq!(memory.current_tokens(), 0);
    }

    #[test]
    fn test_clear_except_system() {
        let mut memory = create_test_memory();

        memory.add_items(vec![
            MemoryItem::system("System"),
            MemoryItem::user_message("User"),
            MemoryItem::assistant_message("Assistant"),
        ]);

        memory.clear_except_system();
        assert_eq!(memory.len(), 1);
        let item = memory.get_items().front().unwrap();
        assert!(matches!(item.item_type, ItemType::System));
    }

    #[test]
    fn test_get_items_by_type() {
        let mut memory = create_test_memory();

        memory.add_items(vec![
            MemoryItem::user_message("User 1"),
            MemoryItem::assistant_message("Assistant 1"),
            MemoryItem::user_message("User 2"),
        ]);

        let user_messages = memory.get_items_by_type(&ItemType::UserMessage);
        assert_eq!(user_messages.len(), 2);
    }

    #[test]
    fn test_get_recent() {
        let mut memory = create_test_memory();

        for i in 0..5 {
            memory.add_item(MemoryItem::user_message(format!("Message {}", i)));
        }

        let recent = memory.get_recent(3);
        assert_eq!(recent.len(), 3);
        // Most recent first
        assert!(recent[0].content.contains("4"));
        assert!(recent[1].content.contains("3"));
        assert!(recent[2].content.contains("2"));
    }

    #[test]
    fn test_search() {
        let mut memory = create_test_memory();

        memory.add_items(vec![
            MemoryItem::user_message("The weather is nice today"),
            MemoryItem::assistant_message("Yes, it's sunny!"),
            MemoryItem::user_message("What about tomorrow's weather?"),
        ]);

        let results = memory.search("weather");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_needs_summarization() {
        let llm = Arc::new(MockLlmProvider::new());
        let config = WorkingMemoryConfig::default().with_max_tokens(100);
        let mut memory = WorkingMemory::new(llm, config);

        // Add enough items to exceed token limit
        for i in 0..20 {
            memory.add_item(MemoryItem::user_message(format!(
                "This is a fairly long message number {} that should help exceed the token limit",
                i
            )));
        }

        assert!(memory.needs_summarization());
    }

    #[test]
    fn test_config_builder() {
        let config = WorkingMemoryConfig::default()
            .with_max_tokens(8192)
            .with_model("gpt-4")
            .with_protected_recent(5);

        assert_eq!(config.max_tokens, 8192);
        assert_eq!(config.target_tokens_after_summarization, 4096);
        assert_eq!(config.summarization_model, "gpt-4");
        assert_eq!(config.protected_recent_items, 5);
    }

    #[test]
    fn test_item_priority() {
        let low = MemoryItem::user_message("Low").with_priority(ItemPriority::Low);
        let high = MemoryItem::user_message("High").with_priority(ItemPriority::High);

        assert!(low.priority < high.priority);
        assert!(ItemPriority::Low < ItemPriority::Normal);
        assert!(ItemPriority::Normal < ItemPriority::High);
        assert!(ItemPriority::High < ItemPriority::Critical);
    }

    #[test]
    fn test_item_metadata() {
        let item =
            MemoryItem::user_message("Test").with_metadata(serde_json::json!({"key": "value"}));

        assert!(item.metadata.is_some());
        let meta = item.metadata.unwrap();
        assert_eq!(meta["key"], "value");
    }

    #[test]
    fn test_summary_item() {
        let summary = MemoryItem::summary("Summary content", 5);
        assert!(matches!(
            summary.item_type,
            ItemType::Summary {
                items_summarized: 5,
                ..
            }
        ));
        assert_eq!(summary.priority, ItemPriority::High);
    }

    #[test]
    fn test_estimate_tokens() {
        // Empty content
        assert_eq!(estimate_tokens(""), 0);

        // Short text - at least 1 token for non-empty content
        assert!(estimate_tokens("test") >= 1);

        // English text should estimate reasonably (~4 chars/token)
        let english = "this is a longer message";
        let tokens = estimate_tokens(english);
        assert!(tokens >= 4 && tokens <= 10, "English estimate: {}", tokens);

        // Code with symbols should estimate higher than pure text
        let code = r#"fn main() { println!("hello"); }"#;
        let code_tokens = estimate_tokens(code);
        let text_of_same_len = "a".repeat(code.len());
        let text_tokens = estimate_tokens(&text_of_same_len);
        assert!(
            code_tokens >= text_tokens,
            "Code ({}) should estimate >= text ({})",
            code_tokens,
            text_tokens
        );

        // Non-ASCII should estimate more tokens per byte
        let cjk = "\u{4f60}\u{597d}\u{4e16}\u{754c}"; // "你好世界"
        let cjk_tokens = estimate_tokens(cjk);
        assert!(cjk_tokens >= 1, "CJK estimate: {}", cjk_tokens);
    }

    #[test]
    fn test_export_import() {
        let mut memory = create_test_memory();

        memory.add_items(vec![
            MemoryItem::user_message("Message 1"),
            MemoryItem::assistant_message("Response 1"),
        ]);

        let exported = memory.export().unwrap();

        let mut new_memory = create_test_memory();
        let count = new_memory.import(&exported).unwrap();

        assert_eq!(count, 2);
        assert_eq!(new_memory.len(), 2);
    }

    #[test]
    fn test_recalculate_tokens() {
        let mut memory = create_test_memory();

        memory.add_item(MemoryItem::user_message("Test message"));
        let initial = memory.current_tokens();

        // Manually mess with tokens (simulating external modification)
        memory.current_tokens = 0;

        memory.recalculate_tokens();
        assert_eq!(memory.current_tokens(), initial);
    }

    #[tokio::test]
    async fn test_summarize_not_needed() {
        let llm = Arc::new(MockLlmProvider::new());
        let config = WorkingMemoryConfig::default();
        let mut memory = WorkingMemory::new(llm, config);

        // Add just a few items - not enough to trigger summarization
        memory.add_item(MemoryItem::user_message("Hello"));
        memory.add_item(MemoryItem::assistant_message("Hi!"));

        // Should not error, just skip summarization
        memory.summarize().await.unwrap();
        assert_eq!(memory.summarization_count(), 0);
    }

    #[tokio::test]
    async fn test_summarize_with_mock_llm() {
        let llm = Arc::new(MockLlmProvider::always(
            "This is a summary of the conversation.",
        ));
        let config = WorkingMemoryConfig::default()
            .with_max_tokens(50)
            .with_protected_recent(2);
        let mut memory = WorkingMemory::new(llm, config);

        // Add enough items to trigger summarization
        for i in 0..10 {
            memory.add_item(MemoryItem::user_message(format!(
                "This is message number {} with enough text to accumulate tokens",
                i
            )));
        }

        let initial_count = memory.len();
        assert!(memory.needs_summarization());

        memory.summarize().await.unwrap();

        assert_eq!(memory.summarization_count(), 1);
        // Should have fewer items after summarization
        assert!(memory.len() < initial_count);

        // Should have a summary item
        let items = memory.get_items();
        let has_summary = items
            .iter()
            .any(|item| matches!(item.item_type, ItemType::Summary { .. }));
        assert!(has_summary);
    }

    #[test]
    fn test_format_item_type() {
        assert_eq!(format_item_type(&ItemType::System), "System");
        assert_eq!(format_item_type(&ItemType::UserMessage), "User");
        assert_eq!(format_item_type(&ItemType::AssistantMessage), "Assistant");
        assert_eq!(format_item_type(&ItemType::Observation), "Observation");
        assert_eq!(format_item_type(&ItemType::Thought), "Thought");
    }

    #[test]
    fn test_working_memory_error_display() {
        let err = WorkingMemoryError::LlmError("Connection failed".to_string());
        assert!(err.to_string().contains("LLM error"));

        let err = WorkingMemoryError::ConfigError("Invalid config".to_string());
        assert!(err.to_string().contains("Configuration error"));

        let err = WorkingMemoryError::EmptyMemory;
        assert!(err.to_string().contains("empty"));

        let err = WorkingMemoryError::ItemNotFound(Uuid::new_v4());
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_default_config() {
        let config = WorkingMemoryConfig::default();
        assert_eq!(config.max_tokens, 4096);
        assert_eq!(config.target_tokens_after_summarization, 2048);
        assert_eq!(config.protected_recent_items, 3);
        assert_eq!(config.summarization_temperature, 0.3);
    }
}
