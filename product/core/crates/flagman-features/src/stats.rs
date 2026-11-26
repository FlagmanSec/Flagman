//! Running statistics in constant memory.
//!
//! A flow can have millions of packets, and the sensor may follow 100,000
//! flows at once, so no list of values is ever kept. Each new value updates
//! a count, a mean and a sum of squared differences (Welford's method, which
//! stays accurate where the textbook "sum of squares" formula loses
//! precision), plus the smallest and largest value.

/// Count, mean, standard deviation, minimum and maximum of whole numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RunningStats {
    count: u32,
    mean: f64,
    /// Sum of squared differences from the mean.
    m2: f64,
    min: u32,
    max: u32,
}

impl RunningStats {
    pub fn add(&mut self, value: u32) {
        self.count = self.count.saturating_add(1);
        let x = f64::from(value);
        let delta = x - self.mean;
        self.mean += delta / f64::from(self.count);
        self.m2 += delta * (x - self.mean);
        if self.count == 1 {
            self.min = value;
            self.max = value;
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    /// `None` before the first value.
    pub fn mean(&self) -> Option<f64> {
        (self.count > 0).then_some(self.mean)
    }

    /// Population standard deviation (divided by the count): 0 for a single
    /// value, `None` before the first one.
    pub fn std(&self) -> Option<f64> {
        (self.count > 0).then(|| (self.m2 / f64::from(self.count)).max(0.0).sqrt())
    }

    pub fn min(&self) -> Option<u32> {
        (self.count > 0).then_some(self.min)
    }

    pub fn max(&self) -> Option<u32> {
        (self.count > 0).then_some(self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_worked_example() {
        // 2, 4, 4, 4, 5, 5, 7, 9: mean 5, population standard deviation 2.
        let mut stats = RunningStats::default();
        for value in [2, 4, 4, 4, 5, 5, 7, 9] {
            stats.add(value);
        }
        assert_eq!(stats.count(), 8);
        assert_eq!(stats.mean(), Some(5.0));
        assert_eq!(stats.std(), Some(2.0));
        assert_eq!((stats.min(), stats.max()), (Some(2), Some(9)));
    }

    #[test]
    fn empty_and_single_values() {
        let mut stats = RunningStats::default();
        assert_eq!((stats.mean(), stats.std(), stats.min()), (None, None, None));
        stats.add(1_500);
        assert_eq!((stats.mean(), stats.std()), (Some(1_500.0), Some(0.0)));
    }

    #[test]
    fn large_values_keep_their_precision() {
        // The naive formula (sum of squares minus square of sum) loses the
        // variance of values around a large mean; Welford's method does not.
        let mut stats = RunningStats::default();
        for value in [4_000_000_001u32, 4_000_000_003, 4_000_000_005] {
            stats.add(value);
        }
        let std = stats.std().unwrap();
        assert!((std - (8.0f64 / 3.0).sqrt()).abs() < 1e-6, "std = {std}");
    }
}
