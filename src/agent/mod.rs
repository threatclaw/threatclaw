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
mod commands;
pub mod compaction;
pub mod context_monitor;
pub mod cost_guard;
pub mod cyber_scheduler;
mod dispatcher;
pub mod cloud_caller;
pub mod binary_verify;
pub mod command_interpreter;
pub mod conversational_bot;
pub mod executor;
pub mod executor_ssh;
pub mod hitl_bridge;
pub mod hitl_nonce;
pub mod intelligence_engine;
pub mod kill_switch;
pub mod llm_router;
pub mod memory;
pub mod mode_manager;
pub mod notification_router;
pub mod production_safeguards;
pub mod observation_collector;
pub mod prompt_builder;
pub mod react_cycle;
pub mod react_runner;
pub mod remediation_whitelist;
pub mod soul;
pub mod test_scenarios;
pub mod tool_output_wrapper;
mod heartbeat;
pub mod job_monitor;
mod router;
pub mod routine;
pub mod routine_engine;
pub(crate) mod scheduler;
mod self_repair;
pub mod session;
mod session_manager;
pub mod submission;
pub mod task;
mod thread_ops;
pub mod undo;

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
