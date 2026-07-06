//! Command dispatch: validates the caller's role against a handler's
//! required capability *before* calling into it, mirroring the backend's
//! `require_capability` dependency (check first, execute second) — see
//! `EC-PKI-Playground/backend/src/app/core/authz.py`.
//!
//! The role check lives centrally in `CommandRegistry::dispatch`, not in
//! each handler: it's structurally impossible for a new handler to forget
//! its own gate.

use std::collections::HashMap;

use serde_json::Value;

use crate::{
    authz::{Capability, Role},
    report::ProgressSink
};

pub struct CommandContext<'a> {
    pub params: &'a HashMap<String, String>,
    pub progress: &'a dyn ProgressSink
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("missing required parameter '{0}'")]
    MissingParam(String),
    #[error("invalid parameter '{name}': {reason}")]
    InvalidParam { name: String, reason: String }
}

pub trait CommandHandler: Send + Sync {
    fn name(&self) -> &'static str;
    fn required_capability(&self) -> Capability;
    fn execute(&self, ctx: &CommandContext) -> Result<Value, CommandError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("unknown command '{0}'")]
    UnknownCommand(String),
    #[error(
        "role {role:?} lacks capability {required:?} required by '{command}'"
    )]
    Forbidden {
        command: String,
        role: Role,
        required: Capability
    },
    #[error(transparent)]
    Command(#[from] CommandError)
}

#[derive(Default)]
pub struct CommandRegistry {
    handlers: HashMap<&'static str, Box<dyn CommandHandler>>
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, handler: Box<dyn CommandHandler>) {
        self.handlers.insert(handler.name(), handler);
    }

    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    pub fn dispatch(
        &self,
        name: &str,
        role: Role,
        params: HashMap<String, String>,
        progress: &dyn ProgressSink
    ) -> Result<Value, DispatchError> {
        let handler = self
            .handlers
            .get(name)
            .ok_or_else(|| DispatchError::UnknownCommand(name.to_string()))?;

        let required = handler.required_capability();
        if !role.has(required) {
            return Err(DispatchError::Forbidden {
                command: name.to_string(),
                role,
                required
            });
        }

        let ctx = CommandContext {
            params: &params,
            progress
        };
        Ok(handler.execute(&ctx)?)
    }
}

// See tests/registry_dispatch.rs for dispatch/gating behavior tests
// (kept as an integration test against the public API rather than inline,
// since it exercises the registry as an external caller would).
