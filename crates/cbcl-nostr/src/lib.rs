//! cbcl-nostr: CBCL-over-Nostr event types and S-expression codec.
//!
//! Provides:
//! - Typed wrappers for kind 21111 (`AgentMessage`) and kind 31111
//!   (`AgentDialect`) Nostr events, with strongly-typed tag enums.
//! - Parsing and serialization of CBCL S-expressions in Nostr event
//!   `content` fields, plus JSON-safe encoding of typed CBCL atoms.

#![forbid(unsafe_code)]

pub mod agent_discovery;
pub mod agent_profile;
pub mod commerce_dialect;
pub mod conversation_threads;
pub mod dialect_negotiation;
pub mod dialect_safety;
pub mod event_signing;
pub mod event_types;
pub mod gift_wrap;
pub mod inbox_handler;
pub mod message_builder;
pub mod open_task_market;
pub mod payment_safety;
pub mod relay_pool;
pub mod reputation_query;
pub mod sexpr_codec;
pub mod spam_prevention;
pub mod subscription_manager;
pub mod zap_integration;
