//! Note-related database operations.

pub mod sapling;

#[cfg(feature = "orchard")]
pub mod orchard;

#[cfg(feature = "transparent-inputs")]
pub mod transparent;
