//! The behaviour GRU, loaded from the weights the trainer exported.
//!
//! # Why the arithmetic is written out here
//!
//! The service has no tensor runtime and does not need one: the model is 33
//! inputs, 32 hidden units and one output, and a forward pass is three
//! matrix-vector products per event over sixty-four events. Written out, the
//! weights are the only thing that ships, the model cannot be retrained at
//! runtime, and the arithmetic does not change under the service's feet.
//!
//! # The format
//!
//! `train_behaviour.py` writes:
//!
//! ```text
//! "WENLGRU1" | u32 width | u32 hidden | 11 * (u32 count, count * f32 little-endian)
//! ```
//!
//! in the order `w_z, u_z, b_z, w_r, u_r, b_r, w_h, u_h, b_h, w_o, b_o`. The
//! order is the contract between the trainer and this reader; a model from a
//! different trainer is refused rather than read into the wrong matrix.
//!
//! # The padding rule
//!
//! A story with fewer than [`LENGTH`](crate::LENGTH) events is padded at the
//! *front* with zero vectors, exactly as the trainer does. Padding at the end
//! would leave the hidden state resting on zeros, which is not a behaviour; the
//! front keeps the last event last.

use crate::sequence::{Features, LENGTH, WIDTH};

/// The magic the trainer writes, and the only version this reader accepts.
const MAGIC: &[u8; 8] = b"WENLGRU1";

/// How many hidden units the exported model uses.
///
/// Fixed rather than read and trusted: a model with a different width would load
/// and then compute a hidden state this code has no room for. The header is
/// checked against these numbers.
const HIDDEN: usize = 32;

/// A loaded model.
#[derive(Debug, Clone)]
pub struct Model {
    w_z: Vec<f32>,
    u_z: Vec<f32>,
    b_z: Vec<f32>,
    w_r: Vec<f32>,
    u_r: Vec<f32>,
    b_r: Vec<f32>,
    w_h: Vec<f32>,
    u_h: Vec<f32>,
    b_h: Vec<f32>,
    w_o: Vec<f32>,
    b_o: Vec<f32>,
}

impl Model {
    /// Read a model the trainer wrote, or `None` if the bytes are not one.
    pub fn load(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 || &bytes[..8] != MAGIC {
            return None;
        }
        let width = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
        let hidden = u32::from_le_bytes(bytes[12..16].try_into().ok()?) as usize;
        if width != WIDTH || hidden != HIDDEN {
            return None;
        }
        let mut cursor: usize = 16;
        let mut take = |count: usize| -> Option<Vec<f32>> {
            let bytes_needed = count.checked_mul(4)?;
            let header = cursor.checked_add(4)?;
            if header + bytes_needed > bytes.len() {
                return None;
            }
            let declared = u32::from_le_bytes(bytes[cursor..header].try_into().ok()?) as usize;
            if declared != count {
                return None;
            }
            let mut values = Vec::with_capacity(count);
            for index in 0..count {
                let at = header + index * 4;
                values.push(f32::from_le_bytes(bytes[at..at + 4].try_into().ok()?));
            }
            cursor = header + bytes_needed;
            Some(values)
        };
        let model = Self {
            w_z: take(HIDDEN * WIDTH)?,
            u_z: take(HIDDEN * HIDDEN)?,
            b_z: take(HIDDEN)?,
            w_r: take(HIDDEN * WIDTH)?,
            u_r: take(HIDDEN * HIDDEN)?,
            b_r: take(HIDDEN)?,
            w_h: take(HIDDEN * WIDTH)?,
            u_h: take(HIDDEN * HIDDEN)?,
            b_h: take(HIDDEN)?,
            w_o: take(HIDDEN)?,
            b_o: take(1)?,
        };
        if cursor != bytes.len() {
            return None;
        }
        Some(model)
    }

    /// The probability this story is malicious, in `0.0..=1.0`.
    ///
    /// Runs over exactly [`LENGTH`] events: the story's last sixty-four, front
    /// padded with zeros when there are fewer. The arithmetic is the trainer's,
    /// in the same order, so the two cannot disagree about a score.
    pub fn score(&self, events: &[Features]) -> f32 {
        let mut hidden = [0.0f32; HIDDEN];
        let first = events.len().saturating_sub(LENGTH);
        let padding = LENGTH - events.len().min(LENGTH);
        for _ in 0..padding {
            self.step(&[0.0f32; WIDTH], &mut hidden);
        }
        for event in &events[first..] {
            self.step(&event.0, &mut hidden);
        }
        let mut logit = self.b_o[0];
        for index in 0..HIDDEN {
            logit += self.w_o[index] * hidden[index];
        }
        sigmoid(logit)
    }

    /// One GRU step.
    fn step(&self, input: &[f32; WIDTH], hidden: &mut [f32; HIDDEN]) {
        let reset = self.gate(&self.w_r, &self.u_r, &self.b_r, input, hidden);
        let update = self.gate(&self.w_z, &self.u_z, &self.b_z, input, hidden);
        let mut candidate = [0.0f32; HIDDEN];
        for unit in 0..HIDDEN {
            let mut sum = self.b_h[unit];
            let row = unit * WIDTH;
            for index in 0..WIDTH {
                sum += self.w_h[row + index] * input[index];
            }
            let row = unit * HIDDEN;
            for index in 0..HIDDEN {
                sum += self.u_h[row + index] * (reset[index] * hidden[index]);
            }
            candidate[unit] = sum.tanh();
        }
        for unit in 0..HIDDEN {
            hidden[unit] = (1.0 - update[unit]) * hidden[unit] + update[unit] * candidate[unit];
        }
    }

    /// A gate: `sigmoid(W x + U h + b)`.
    fn gate(
        &self,
        w: &[f32],
        u: &[f32],
        b: &[f32],
        input: &[f32; WIDTH],
        hidden: &[f32; HIDDEN],
    ) -> [f32; HIDDEN] {
        let mut out = [0.0f32; HIDDEN];
        for unit in 0..HIDDEN {
            let mut sum = b[unit];
            let row = unit * WIDTH;
            for index in 0..WIDTH {
                sum += w[row + index] * input[index];
            }
            let row = unit * HIDDEN;
            for index in 0..HIDDEN {
                sum += u[row + index] * hidden[index];
            }
            out[unit] = sigmoid(sum);
        }
        out
    }
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_model() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(WIDTH as u32).to_le_bytes());
        bytes.extend_from_slice(&(HIDDEN as u32).to_le_bytes());
        let mut push = |count: usize| {
            bytes.extend_from_slice(&(count as u32).to_le_bytes());
            for _ in 0..count {
                bytes.extend_from_slice(&0.0f32.to_le_bytes());
            }
        };
        push(HIDDEN * WIDTH);
        push(HIDDEN * HIDDEN);
        push(HIDDEN);
        push(HIDDEN * WIDTH);
        push(HIDDEN * HIDDEN);
        push(HIDDEN);
        push(HIDDEN * WIDTH);
        push(HIDDEN * HIDDEN);
        push(HIDDEN);
        push(HIDDEN);
        push(1);
        bytes
    }

    #[test]
    fn a_zero_model_scores_exactly_half() {
        let model = Model::load(&tiny_model()).expect("the model loads");
        let score = model.score(&[]);
        assert!((score - 0.5).abs() < 1e-6, "{score}");
    }

    #[test]
    fn a_truncated_model_is_refused() {
        let mut bytes = tiny_model();
        bytes.truncate(bytes.len() - 3);
        assert!(Model::load(&bytes).is_none());
    }

    #[test]
    fn the_wrong_magic_is_refused() {
        let mut bytes = tiny_model();
        bytes[0] = b'X';
        assert!(Model::load(&bytes).is_none());
    }

    #[test]
    fn the_wrong_width_is_refused() {
        let mut bytes = tiny_model();
        bytes[8..12].copy_from_slice(&64u32.to_le_bytes());
        assert!(Model::load(&bytes).is_none());
    }

    #[test]
    fn a_story_is_padded_at_the_front_so_the_last_event_is_last() {
        let model = Model::load(&tiny_model()).expect("the model loads");
        let event = Features([0.0; WIDTH]);
        let short = model.score(&[event]);
        let long = model.score(&vec![event; LENGTH]);
        // With every weight zero the score is 0.5 whatever the input, which is
        // what makes this a test of the loop and not of the numbers.
        assert!((short - 0.5).abs() < 1e-6);
        assert!((long - 0.5).abs() < 1e-6);
    }
}
