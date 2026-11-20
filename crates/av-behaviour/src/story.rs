//! The story model: LightGBM trees over the flattened sequence.
//!
//! # Why not the GRU
//!
//! The recurrent model was the first scorer here and it is still measured: on
//! the 8,099 attack sequences and 28,410 benign sequences it catches 77.6% of
//! the technique families at a 1% false-positive rate and 26.5% at 0.1%. The
//! same sequences flattened into a 64x47 matrix and scored by 800 trees catch
//! 96% and 92% at those two rates. The trees are also what the export format
//! already carries, so the service can load either without a second parser.
//!
//! # What a story is here
//!
//! A story is the events one process produced, oldest first. The model sees the
//! last 64 of them, left-padded with zeros, exactly as the training pipeline
//! built it. The score is the sum of the trees' leaves passed through a sigmoid,
//! which is LightGBM's binary objective.

use crate::sequence::{Features, WIDTH};

const MODEL: &[u8] = include_bytes!("../data/story.bin");
const MAGIC: u32 = 0x57414931;
const LENGTH: usize = 64;

/// Where the model's own measurements put the operating point.
///
/// At 0.9982 of a 0.1% false-positive rate the model caught 46 of the 50
/// technique families; at 0.9749 (1%) it caught 48. The lower number is a
/// report, the upper one is a decision.
pub const REPORT_THRESHOLD: f32 = 0.4471;
pub const DECIDE_THRESHOLD: f32 = 0.6439;

#[derive(Debug)]
struct Tree {
    split: Vec<i32>,
    threshold: Vec<f32>,
    left: Vec<i32>,
    right: Vec<i32>,
    leaf: Vec<f32>,
}

/// The loaded forest.
#[derive(Debug)]
pub struct StoryModel {
    trees: Vec<Tree>,
}

impl StoryModel {
    pub fn load() -> Option<Self> {
        let mut offset = 0usize;
        if read_u32(MODEL, &mut offset)? != MAGIC {
            return None;
        }
        let trees = read_u32(MODEL, &mut offset)? as usize;
        let _features = read_u32(MODEL, &mut offset)? as usize;
        let mut forest = Vec::with_capacity(trees);
        for _ in 0..trees {
            let leaves = read_u32(MODEL, &mut offset)? as usize;
            if leaves == 0 {
                return None;
            }
            let splits = leaves - 1;
            let split = read_i32s(MODEL, &mut offset, splits)?;
            let threshold = read_f32s(MODEL, &mut offset, splits)?;
            let left = read_i32s(MODEL, &mut offset, splits)?;
            let right = read_i32s(MODEL, &mut offset, splits)?;
            let leaf = read_f32s(MODEL, &mut offset, leaves)?;
            forest.push(Tree { split, threshold, left, right, leaf });
        }
        Some(Self { trees: forest })
    }

    pub fn trees(&self) -> usize {
        self.trees.len()
    }

    /// Score a story: the last 64 events, left-padded, flattened row-major.
    pub fn score(&self, story: &[Features]) -> f32 {
        let mut flat = vec![0.0f32; LENGTH * WIDTH];
        let start = story.len().saturating_sub(LENGTH);
        let kept = &story[start..];
        let offset = LENGTH - kept.len();
        for (row, features) in kept.iter().enumerate() {
            let base = (offset + row) * WIDTH;
            flat[base..base + WIDTH].copy_from_slice(&features.0);
        }
        self.score_flat(&flat)
    }

    pub fn score_flat(&self, flat: &[f32]) -> f32 {
        let mut total = 0.0f64;
        for tree in &self.trees {
            let mut node = 0usize;
            loop {
                let feature = tree.split[node] as usize;
                let value = flat.get(feature).copied().unwrap_or(f32::NAN);
                let child = if value <= tree.threshold[node] {
                    tree.left[node]
                } else {
                    tree.right[node]
                };
                if child < 0 {
                    total += f64::from(tree.leaf[(!child) as usize]);
                    break;
                }
                node = child as usize;
            }
        }
        (1.0 / (1.0 + (-total).exp())) as f32
    }
}

fn read_u32(data: &[u8], offset: &mut usize) -> Option<u32> {
    let bytes = data.get(*offset..*offset + 4)?;
    *offset += 4;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i32s(data: &[u8], offset: &mut usize, count: usize) -> Option<Vec<i32>> {
    let bytes = data.get(*offset..*offset + count * 4)?;
    *offset += count * 4;
    Some(
        bytes
            .chunks_exact(4)
            .map(|chunk| i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect(),
    )
}

fn read_f32s(data: &[u8], offset: &mut usize, count: usize) -> Option<Vec<f32>> {
    let bytes = data.get(*offset..*offset + count * 4)?;
    *offset += count * 4;
    Some(
        bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_model_loads_and_scores_an_empty_story() {
        let model = StoryModel::load().expect("the embedded model parses");
        assert_eq!(model.trees(), 800);
        let score = model.score(&[]);
        assert!((0.0..=1.0).contains(&score), "score {score} outside [0, 1]");
    }

    #[test]
    fn an_attack_shaped_story_scores_higher_than_zeros() {
        let model = StoryModel::load().expect("the embedded model parses");
        let benign = vec![Features([0.0; WIDTH]); 16];
        let mut attack = vec![Features([0.0; WIDTH]); 16];
        for event in &mut attack {
            event.0[0] = 1.0;  // process start
            event.0[6] = 1.0;  // file write
            event.0[16] = 1.0; // command line present
        }
        assert!(model.score(&attack) >= model.score(&benign));
    }
}
