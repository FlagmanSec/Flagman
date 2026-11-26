//! Number generators for alert and incident ids.
//!
//! The daemon reads the highest id already stored in the database at start-up
//! and continues from there, so ids stay unique across restarts.

/// Hands out increasing ids, starting after `last_used`.
#[derive(Debug, Clone)]
pub struct IdGenerator {
    last_used: u64,
}

impl IdGenerator {
    pub fn starting_after(last_used: u64) -> IdGenerator {
        IdGenerator { last_used }
    }

    pub fn next_id(&mut self) -> u64 {
        self.last_used += 1;
        self.last_used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continues_after_the_last_stored_id() {
        let mut ids = IdGenerator::starting_after(41);
        assert_eq!(ids.next_id(), 42);
        assert_eq!(ids.next_id(), 43);
    }
}
