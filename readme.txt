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
* Uploads: only *.paio accepted, sent in 8 MB pieces each checked by SHA-256, the PAIO1
  magic is verified on the first piece and the whole archive structure after the last.
* The archive is treated as untrusted input (0.1.5):
  - Executable files (php, phtml, phar, inc, cgi, ...) are restored only into plugins/,
    themes/, mu-plugins/, languages/, plus wp-content/index.php and the WordPress drop-ins
    (db.php, advanced-cache.php, ... - listed after import, check them). Anywhere else,
    uploads/ above all, they are refused and listed. WP-CLI `--allow-php-anywhere` overrides.
  - .user.ini and php.ini are never restored. An .htaccess is restored only if it does not
    map handlers/types to PHP/CGI/SSI, enable ExecCGI/Includes, or set php_* values.
  - database.sql is checked statement by statement BEFORE anything is written: only
    SET NAMES / sql_mode / FOREIGN_KEY_CHECKS, DROP TABLE IF EXISTS, CREATE TABLE (no
    AS SELECT, DATA DIRECTORY or CONNECTION) and INSERT INTO, all on tables with this
    site's prefix. Anything else refuses the whole import.
  - URL rewriting never calls unserialize(): serialized values are rewritten token by token,
    so a crafted value cannot instantiate a PHP object.
  - Existing symlinks at a destination are replaced, not written through.
  - On a site with DISALLOW_FILE_MODS the wp-admin GUI refuses to restore files (database
    only). Restore files with WP-CLI, which needs shell access.
* Export does not follow symlinks; skipped links are listed so their targets can be copied
  separately.
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
  wp paio import <file> --allow-php-anywhere   # also restore PHP outside code dirs (checked archives only)

== Usage: wp-admin GUI ==

  Tools -> PAIO Migration
  - "Create export archive" builds a .paio in the storage dir.
  - Upload a .paio (any size, sent in pieces), then click Import next to it in the list.
    Tick "Database only" to leave wp-content untouched.
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

== Server-side protection ==

The .htaccess in paio-backups/ is not enough on hosts where a global <Location "/"> grant
overrides per-directory Require rules (the RTP fleet is one). Deny the storage path in the
server config instead, e.g. /etc/httpd/conf/extra/99-deny-paio-backups.conf:

  <LocationMatch "/wp-content/paio-backups/">
      RewriteEngine On
      RewriteRule .* - [F,L]
  </LocationMatch>

Downloads keep working: they go through admin-ajax.php (paio_download), not that path.

== Tests ==

  php tests/paio-unit.php                          # pure checks, no WordPress needed
  wp eval-file wp-content/plugins/paio/tests/paio-pct.php      # "%" round trip
  wp eval-file wp-content/plugins/paio/tests/paio-hostile.php  # hostile archive (TEST SITE ONLY)
