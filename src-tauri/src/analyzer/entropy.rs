/// Calcul entropie de Shannon (0.0 - 8.0).
/// Valeur > 7.2 → forte suspicion de packer/chiffrement.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "entropie uniforme doit être ~8.0, got {e}");
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0xAA; 1000];
        let e = shannon_entropy(&data);
        assert!(e < 0.01, "entropie constante doit être ~0.0, got {e}");
    }
}
