//! Signatures stockées à l'envers pour éviter un faux positif sur NOTRE binaire.
//!
//! Écrites en clair, les chaînes de détection (notes de rançon, commandes
//! d'effacement de sauvegardes, chaîne EICAR…) font classer l'exécutable
//! lui-même comme malware par les antivirus. On les stocke inversées octet par
//! octet — une transformation triviale, pas un chiffrement — et on les remet à
//! l'endroit en mémoire au moment de l'analyse. Aucune sécurité n'en dépend :
//! c'est uniquement pour que le scanner d'un utilisateur ne bloque pas le scanner.

pub const fn flip<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = s[N - 1 - i];
        i += 1;
    }
    out
}

pub fn restore(reversed: &[u8]) -> Vec<u8> {
    reversed.iter().rev().copied().collect()
}

pub fn restore_str(reversed: &[u8]) -> String {
    String::from_utf8_lossy(&restore(reversed)).into_owned()
}

/// Octets inversés (`&'static [u8]`) d'un littéral `&str`.
#[macro_export]
macro_rules! sig {
    ($s:literal) => {{
        const R: &[u8] = &$crate::obf::flip::<{ $s.len() }>($s.as_bytes());
        R
    }};
}

/// Octets inversés (`&'static [u8]`) d'un littéral `b"…"`.
#[macro_export]
macro_rules! sig_bytes {
    ($s:literal) => {{
        const R: &[u8] = &$crate::obf::flip::<{ $s.len() }>($s);
        R
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aller_retour() {
        assert_eq!(restore_str(crate::sig!("temoin abc")), "temoin abc");
        assert_eq!(restore(crate::sig_bytes!(b"\x4d\x5a\x90\x00")), vec![0x4d, 0x5a, 0x90, 0x00]);
    }
}
