//! Analyse un fichier en ligne de commande avec les reglages de l'utilisateur
//! (cles du trousseau), sans interface : `cargo run --release --example scan -- <fichier>`.
//! `--offline` ignore les sources en ligne, `-v` detaille preuves et facteurs.

use file_scanner_lib::config::settings;
use file_scanner_lib::report::types::AppSettings;
use file_scanner_lib::scanner::pipeline::scan_file;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let offline = args.iter().any(|a| a == "--offline");
    let verbose = args.iter().any(|a| a == "-v");
    let s = if offline {
        AppSettings { intel_free_lookups: false, ..Default::default() }
    } else {
        settings::load().unwrap_or_default()
    };
    for path in args.iter().filter(|a| !a.starts_with('-')) {
        match scan_file(path, &s).await {
            Ok(r) => {
                let sig = r.pe_info.as_ref().map(|p| p.signature.label.clone()).unwrap_or_default();
                println!(
                    "{} | {:?} {} % ({}) | signature: {} | IoC: {}",
                    r.file_name, r.verdict, r.verdict_score, r.assessment.label, sig, r.ioc_list.len()
                );
                for d in r.detections.iter().take(8) {
                    println!("    {:>2} %  {}  [base {}]", d.confidence, d.title, d.base_confidence);
                    if verbose {
                        for e in d.evidence.iter().take(6) {
                            println!("           - {e}");
                        }
                        for f in &d.factors {
                            println!("           {:+} {}", f.delta, f.label);
                        }
                    }
                }
            }
            Err(e) => println!("{path} | ERREUR {e}"),
        }
    }
}
