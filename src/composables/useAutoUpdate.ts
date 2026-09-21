// Mise a jour automatique — meme mecanique que Nitrite.
//
// Le plugin officiel de Tauri lit un manifeste signe sur
// filescanner-app.heiphaistos.org/maj/latest.json, telecharge l'installeur NSIS
// leger, le lance, et arrete l'application lui-meme (`process::exit(0)` cote
// Rust) en passant /R a NSIS pour qu'elle redemarre. Rien a relancer nous-memes.
//
// Nitrite a en plus un chemin « portable » : le plugin ne sait pas remplacer un
// executable sur place sous Windows. FileScanner ne livre que l'installeur NSIS,
// donc ce second chemin n'a pas de cible ici et n'est pas repris.

import { check } from '@tauri-apps/plugin-updater'
import { ask, message } from '@tauri-apps/plugin-dialog'

/**
 * Cherche une mise a jour, la propose, l'installe et redemarre.
 *
 * @param silencieux true = ne rien afficher s'il n'y a rien ou si le canal est
 *                   injoignable (verification au demarrage) ; false = bouton
 *                   « Verifier les mises a jour ».
 * @returns true si une mise a jour a ete lancee.
 */
export async function checkForUpdate(silencieux = true): Promise<boolean> {
  // En dev le binaire n'est pas installe : rien a remplacer.
  if (import.meta.env.DEV) return false

  try {
    const update = await check()
    if (!update) {
      if (!silencieux) await message('FileScanner est a jour.', { title: 'Mise a jour' })
      return false
    }

    const accepte = await ask(
      `FileScanner ${update.version} est disponible (vous avez la ${update.currentVersion}).` +
        (update.body ? `\n\n${update.body}` : '') +
        '\n\nVoulez-vous la mettre a jour maintenant ? L\'application redemarrera.',
      { title: 'Une nouvelle version est sortie', kind: 'info' },
    )
    if (!accepte) return false

    // Ne rend jamais la main : le plugin arrete l'application pour laisser
    // l'installeur remplacer les fichiers, puis NSIS la relance.
    await update.downloadAndInstall()
    return true
  } catch (e) {
    // Canal injoignable, serveur en panne, signature refusee : l'utilisateur
    // continue de travailler avec la version qu'il a.
    console.error('[maj] verification impossible', e)
    if (!silencieux) {
      await message(`Verification impossible : ${String(e)}`, {
        title: 'Mise a jour',
        kind: 'error',
      })
    }
    return false
  }
}
