//! Local laboratory management. All operations require lab mode, target a
//! compose file inside the configured lab root, and bind to loopback only.

mod manager;
mod mock;

pub use manager::{Lab, LabManager};
pub use mock::serve_mock_lab;
