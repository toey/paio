=== PAIO Migration ===
Full-site WordPress migration (database + wp-content) for the RTP fleet.
A clean, authenticated, auditable replacement for the cracked
"All-In-One WP Migration With Import" plugin.

== Why this plugin exists ==

The cracked AIO plugin that keeps re-appearing on the fleet is dangerous for two
reasons, and PAIO is built specifically to not repeat either:

1. It registered `wp_ajax_nopriv_ai1wm_import` -> ANY unauthenticated visitor could
   POST an archive and have it restored = remote code execution.
   PAIO has ZERO `wp_ajax_nopriv_*` hooks. Every entry point (GUI AJAX and WP-CLI)
   requires a logged-in administrator (`manage_options`) and, for the GUI, a valid
   per-action nonce.

2. The nulled copies shipped with a backdoor (advanced-settings.php cookie-arith).
   PAIO is plain, readable PHP: no eval, no base64/gzinflate payloads, no remote
   calls, no proc_open (so it runs under the fleet's snuffleupagus hardening).

== Security properties ==

* Archive storage: wp-content/paio-backups/<random-token>/ with a deny-all .htaccess
  (also disables the PHP handler), web.config, and index.php guards. Not web-reachable.
* Import path safety: every file path from an archive goes through PAIO_Security::safe_join()
  which rejects absolute paths, drive/UNC paths, null bytes and any ".." traversal, and
  confines extraction under wp-content. A hostile path aborts the whole import.
* Uploads: only *.paio accepted, and the PAIO1 magic is verified before the file is stored.
* DB handling is via $wpdb only (no mysqldump/proc_open). URL + table-prefix rewriting on
  import is serialization-safe (lengths are recomputed).

== Usage: WP-CLI (recommended for large sites) ==

  wp paio export                 # -> auto-named archive in the storage dir
  wp paio export /path/out.paio  # -> explicit destination
  wp paio list                   # list stored archives
  wp paio import <file>          # overwrite this site from an archive
  wp paio import <file> --skip-db        # files only
  wp paio import <file> --skip-files     # database only
  wp paio import <file> --yes            # no confirmation prompt

== Usage: wp-admin GUI ==

  Tools -> PAIO Migration
  - "Create export archive" builds a .paio in the storage dir.
  - Upload a .paio, then click Import next to it in the list.
  - Download / Delete stored archives.
  Note: a single web request is bound by PHP max_execution_time. For big sites use WP-CLI.

== Archive format (.paio) ==

  PAIO1\n
  {"path":"package.json","size":N,"mtime":N}\n <payload>\n
  {"path":"database.sql","size":N,"mtime":N}\n <payload>\n
  {"path":"wp-content/...","size":N,"mtime":N}\n <payload>\n
  ...
  PAIO_END\n

  Streamable in both directions; no file is ever fully held in memory.

== Not included (by design, for v0.1) ==

* No chunked/background web import (use WP-CLI for very large sites).
* Does not migrate files outside wp-content (wp-config.php, root .htaccess are per-host).
* Same-DB-server assumed; cross-server moves still work via export file -> import file.
