//! Profile inventory: search, filter and render as JSON or a terminal table.

mod inventory;

pub use inventory::{COLUMNS, InventoryRow, render_json, render_table, rows};
