//! The static model: a gradient-boosted forest over the shape of a PE file.
//!
//! Rules convict what somebody has written a rule about. This scores the files
//! no rule mentions, which is where new malware lives, and it is deliberately
//! the *second* opinion: the engine asks for it only when the rules came back
//! clean and nothing proves the file good.

use av_pe::PeFile;

const MODEL: &[u8] = include_bytes!("../data/static_port.bin");

const MAGIC: u32 = 0x57414931;

/// Where a score becomes an accusation.
pub const MALICIOUS_THRESHOLD: f32 = 0.1716;
pub const SUSPICIOUS_THRESHOLD: f32 = 0.0916;

struct Tree {
    split: Vec<i32>,
    threshold: Vec<f32>,
    left: Vec<i32>,
    right: Vec<i32>,
    leaf: Vec<f32>,
}

/// The loaded forest.
pub struct StaticModel {
    trees: Vec<Tree>,
}

impl StaticModel {
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

    /// The probability that a feature vector is malicious.
    ///
    /// Either child of a split can be a leaf, encoded as a negative number:
    /// `!child` is the leaf's index. Checking only the left child was a real bug
    /// here, found by a traversal that looped on the right-hand branch of the
    /// eleventh tree.
    pub fn score(&self, features: &[f32]) -> f32 {
        let mut total = 0.0f64;
        for tree in &self.trees {
            let mut node = 0usize;
            loop {
                let feature = tree.split[node] as usize;
                let value = features.get(feature).copied().unwrap_or(f32::NAN);
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

/// Score a buffer, if it is a PE at all.
pub fn score(data: &[u8]) -> Option<f32> {
    let model = StaticModel::load()?;
    let features = features(data)?;
    Some(model.score(&features))
}

/// The 522 numbers, in the order the training pipeline computed them.
pub fn features(data: &[u8]) -> Option<Vec<f32>> {
    let pe = PeFile::parse(data).ok()?;
    let mut features = Vec::with_capacity(522);

    let mut histogram = [0f32; 256];
    for &byte in data {
        histogram[byte as usize] += 1.0;
    }
    features.extend_from_slice(&histogram);
    features.extend_from_slice(&byte_entropy_histogram(data));

    let mut virtual_size = 0f64;
    let mut entropies = Vec::with_capacity(pe.sections.len());
    for section in &pe.sections {
        virtual_size += f64::from(section.virtual_size);
        entropies.push(section_entropy(
            data,
            section.pointer_to_raw_data as usize,
            section.size_of_raw_data as usize,
        ));
    }
    features.push(data.len() as f32);
    features.push(virtual_size as f32);
    features.push(pe.machine() as f32);
    features.push(pe.subsystem() as f32);
    features.push(pe.characteristics() as f32);
    features.push(pe.dll_characteristics() as f32);
    features.push(pe.sections.len() as f32);
    if entropies.is_empty() {
        features.extend_from_slice(&[0.0, 0.0, 0.0]);
    } else {
        let mean = entropies.iter().sum::<f32>() / entropies.len() as f32;
        let max = entropies.iter().copied().fold(f32::MIN, f32::max);
        let min = entropies.iter().copied().fold(f32::MAX, f32::min);
        features.extend_from_slice(&[mean, max, min]);
    }
    Some(features)
}

/// The byte/entropy joint histogram: 16 entropy bins by 16 byte-value bins.
fn byte_entropy_histogram(data: &[u8]) -> [f32; 256] {
    const WINDOW: usize = 2048;
    const STEP: usize = 1024;
    let mut output = [0f32; 256];
    if data.len() < WINDOW {
        add_block(&mut output, data);
        return output;
    }
    let mut offset = 0usize;
    while offset + WINDOW <= data.len() {
        add_block(&mut output, &data[offset..offset + WINDOW]);
        offset += STEP;
    }
    output
}

fn add_block(output: &mut [f32; 256], block: &[u8]) {
    let mut counts = [0f32; 16];
    for &byte in block {
        counts[(byte >> 4) as usize] += 1.0;
    }
    let total = block.len().max(1) as f32;
    let mut entropy = 0.0f32;
    for count in counts {
        if count > 0.0 {
            let probability = count / total;
            entropy -= probability * probability.log2();
        }
    }
    entropy *= 2.0;
    let mut bin = (entropy * 2.0) as usize;
    if bin >= 16 {
        bin = 15;
    }
    for (index, count) in counts.iter().enumerate() {
        output[bin * 16 + index] += count;
    }
}

fn section_entropy(data: &[u8], offset: usize, size: usize) -> f32 {
    let end = offset.saturating_add(size).min(data.len());
    if offset >= end {
        return 0.0;
    }
    let mut counts = [0f32; 256];
    for &byte in &data[offset..end] {
        counts[byte as usize] += 1.0;
    }
    let total = (end - offset) as f32;
    let mut entropy = 0.0f32;
    for count in counts {
        if count > 0.0 {
            let probability = count / total;
            entropy -= probability * probability.log2();
        }
    }
    entropy
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
    fn the_model_loads_and_scores_a_vector() {
        let model = StaticModel::load().expect("the embedded model parses");
        assert_eq!(model.trees(), 500);
        let score = model.score(&[0.0; 522]);
        assert!((0.0..=1.0).contains(&score), "score {score} outside [0, 1]");
    }

    #[test]
    fn a_small_file_still_gets_an_entropy_histogram() {
        let histogram = byte_entropy_histogram(b"hello world");
        let total: f32 = histogram.iter().sum();
        assert!((total - 11.0).abs() < 0.01, "total {total}");
    }

    #[test]
    fn a_section_entropy_is_between_zero_and_eight() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let entropy = section_entropy(&data, 0, data.len());
        assert!((entropy - 8.0).abs() < 0.01, "entropy {entropy}");
    }

    #[test]
    fn a_non_pe_has_no_features() {
        assert!(features(b"not a portable executable").is_none());
    }
}
