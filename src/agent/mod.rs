//! Core agent logic.
//!
//! The agent orchestrates:
//! - Message routing from channels
//! - Job scheduling and execution
//! - Tool invocation with safety
//! - Self-repair for stuck jobs
//! - Proactive heartbeat execution
//! - Routine-based scheduled and reactive jobs
//! - Turn-based session management with undo
//! - Context compaction for long conversations

mod agent_loop;
pub mod agentic_loop;
mod attachments;
pub mod backup_manager;
pub mod binary_verify;
pub mod cloud_caller;
pub mod cloud_intent;
pub mod command_interpreter;
mod commands;
pub mod compaction;
pub mod context_monitor;
pub mod conversation_mode;
pub mod conversational_bot;
pub mod cost_guard;
pub mod cyber_scheduler;
mod dispatcher;
pub mod executor;
pub mod executor_ssh;
pub mod fingerprint;
mod heartbeat;
pub mod hitl_bridge;
pub mod hitl_nonce;
pub mod incident_dossier;
pub mod intelligence_engine;
pub mod investigation;
pub mod investigation_skills;
pub mod ioc_bloom;
pub mod ip_classifier;
pub mod job_monitor;
pub mod kill_switch;
pub mod llm_router;
pub mod llm_schemas;
pub mod memory;
pub mod mode_manager;
pub mod nace_profiles;
pub mod ndr_beacon;
pub mod ndr_dns_tunnel;
pub mod ndr_ja3;
pub mod ndr_ransomware;
pub mod ndr_sni;
pub mod ndr_tls;
pub mod notification_router;
pub mod observation_collector;
pub mod production_safeguards;
pub mod prompt_builder;
pub mod react_cycle;
pub mod react_runner;
pub mod remediation_engine;
pub mod remediation_guard;
pub mod remediation_whitelist;
pub mod retroact;
mod router;
pub mod routine;
pub mod routine_engine;
pub(crate) mod scheduler;
mod self_repair;
pub mod session;
mod session_manager;
pub mod shift_report;
pub mod sigma_engine;
pub mod skill_scheduler;
pub mod soul;
pub mod submission;
pub mod task;
pub mod test_scenarios;
mod thread_ops;
pub mod tool_calling;
pub mod tool_output_wrapper;
pub mod undo;
pub mod validation_mode;
pub mod verdict;

pub(crate) use agent_loop::truncate_for_preview;
pub use agent_loop::{Agent, AgentDeps};
pub use compaction::{CompactionResult, ContextCompactor};
pub use context_monitor::{CompactionStrategy, ContextBreakdown, ContextMonitor};
pub use heartbeat::{HeartbeatConfig, HeartbeatResult, HeartbeatRunner, spawn_heartbeat};
pub use router::{MessageIntent, Router};
pub use routine::{Routine, RoutineAction, RoutineRun, Trigger};
pub use routine_engine::RoutineEngine;
pub use scheduler::Scheduler;
pub use self_repair::{BrokenTool, RepairResult, RepairTask, SelfRepair, StuckJob};
pub use session::{PendingApproval, PendingAuth, Session, Thread, ThreadState, Turn, TurnState};
pub use session_manager::SessionManager;
pub use submission::{Submission, SubmissionParser, SubmissionResult};
pub use task::{Task, TaskContext, TaskHandler, TaskOutput};
pub use undo::{Checkpoint, UndoManager};
