//! Lazy port iterator backed by a `PortRange`.

use aloo_core::PortRange;

/// Iterates port numbers from a `PortRange` without materialising the full list.
pub struct PortIterator {
    ranges: Vec<(u16, u16)>,
    range_idx: usize,
    current: u16,
    started: bool,
}

impl PortIterator {
    /// Construct from a `PortRange`.
    pub fn new(range: &PortRange) -> Self {
        let current = range.ranges.first().map(|(s, _)| *s).unwrap_or(0);
        Self { ranges: range.ranges.clone(), range_idx: 0, current, started: false }
    }
}

impl Iterator for PortIterator {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ranges.is_empty() {
            return None;
        }
        if !self.started {
            self.started = true;
            return Some(self.current);
        }
        let (_, end) = self.ranges[self.range_idx];
        if self.current < end {
            self.current += 1;
            Some(self.current)
        } else {
            self.range_idx += 1;
            if self.range_idx >= self.ranges.len() {
                return None;
            }
            let (start, _) = self.ranges[self.range_idx];
            self.current = start;
            Some(self.current)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_port() {
        let r = PortRange { ranges: vec![(443, 443)] };
        assert_eq!(PortIterator::new(&r).collect::<Vec<_>>(), vec![443]);
    }

    #[test]
    fn range_of_three() {
        let r = PortRange { ranges: vec![(8080, 8082)] };
        assert_eq!(PortIterator::new(&r).collect::<Vec<_>>(), vec![8080, 8081, 8082]);
    }

    #[test]
    fn two_disjoint_ranges() {
        let r = PortRange { ranges: vec![(80, 81), (443, 444)] };
        assert_eq!(PortIterator::new(&r).collect::<Vec<_>>(), vec![80, 81, 443, 444]);
    }

    #[test]
    fn empty_range() {
        let r = PortRange { ranges: vec![] };
        assert!(PortIterator::new(&r).next().is_none());
    }
}
