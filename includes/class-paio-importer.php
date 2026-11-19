<?php
/**
 * Full-site importer: validates a .paio archive, extracts wp-content (every path confined
 * under WP_CONTENT_DIR), then replays database.sql with URL/prefix rewriting.
 *
 * Safety invariants (0.1.5 makes the archive untrusted input, not a trusted backup):
 *   - Reads the manifest first; refuses an archive without a valid PAIO1 magic / package.json.
 *   - Every file path is run through PAIO_Security::safe_join() -> no traversal, no absolute.
 *   - Executable files (php, phtml, phar, inc, cgi...) are restored only into plugins/, themes/,
 *     mu-plugins/, languages/, plus the wp-content index.php and the WordPress drop-ins. Anywhere
 *     else (uploads/ above all) they are refused and listed. `allow_php_anywhere` (WP-CLI only)
 *     turns this off for an operator who has checked the archive.
 *   - .user.ini / php.ini are never restored. .htaccess is restored only when it restricts access
 *     and does not map handlers or change PHP settings (PAIO_Security::htaccess_problem()).
 *   - On a site with DISALLOW_FILE_MODS, the GUI refuses to restore files at all: that constant
 *     is the fleet's answer to stolen admin passwords, and an archive import would be a way round
 *     it. Use WP-CLI (shell access) or a database-only import.
 *   - database.sql is validated statement by statement before anything runs
 *     (PAIO_Database::import()).
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Importer
{
    /**
     * @param string $archive_path  Path to a .paio archive (already stored/uploaded).
     * @param array  $opts          ['skip_db'=>bool, 'skip_files'=>bool, 'via'=>'gui'|'cli',
     *                               'allow_php_anywhere'=>bool (cli only)]
     * @return array summary
     */
    public static function run($archive_path, array $opts = array())
    {
        @set_time_limit(0);
        if (!is_file($archive_path) || !is_readable($archive_path)) {
            throw new RuntimeException('Archive not found or unreadable.');
        }

        $skip_db    = !empty($opts['skip_db']);
        $skip_files = !empty($opts['skip_files']);
        $via        = isset($opts['via']) ? $opts['via'] : 'gui';
        $php_anywhere = ($via === 'cli') && !empty($opts['allow_php_anywhere']);

        if (!$skip_files && $via !== 'cli' && defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS) {
            throw new RuntimeException('This site sets DISALLOW_FILE_MODS, so files (plugins, themes, code) cannot be '
                . 'restored from wp-admin. Import with WP-CLI (wp paio import), or tick "database only".');
        }

        // Pass 0 (0.1.4): structure check first, so a damaged archive is refused with a clear
        // message before anything is written.
        $bad = PAIO_Archive_Reader::verify($archive_path);
        if ($bad !== null) {
            throw new RuntimeException('Archive is damaged, nothing was imported: ' . $bad . '. Copy or download it again.');
        }

        // Pass 1: read + validate the manifest.
        $reader = new PAIO_Archive_Reader();
        $reader->open($archive_path);
        $manifest_json = $reader->read_entry_to_string('package.json');
        $reader->close();

        if ($manifest_json === null) {
            throw new RuntimeException('Not a PAIO archive: package.json missing.');
        }
        $manifest = json_decode($manifest_json, true);
        if (!is_array($manifest) || empty($manifest['generator'])) {
            throw new RuntimeException('Corrupt or unsupported manifest.');
        }

        // Pass 1b: validate the whole SQL dump before a single file or row changes, so a dump
        // that tries anything beyond our own DROP/CREATE/INSERT is refused with nothing touched.
        if (!$skip_db) {
            $sql_check = self::extract_sql($archive_path);
            if ($sql_check !== null) {
                try {
                    PAIO_Database::validate($sql_check, $manifest);
                } finally {
                    @unlink($sql_check);
                }
            }
        }

        $content_root = WP_CONTENT_DIR;
        $sql_tmp = null;
        $files_written = 0;
        $refused = array();      // [path, reason]
        $dropins = array();
        $htaccess = array();     // [tmp, dest, path] checked after extraction

        // Pass 2: stream the archive, extract wp-content, capture database.sql to a temp file.
        $reader = new PAIO_Archive_Reader();
        $reader->open($archive_path);
        $reader->each(function ($header) use (&$sql_tmp, $content_root, $skip_db, $skip_files, $php_anywhere,
                                              &$files_written, &$refused, &$dropins, &$htaccess) {
            $path = $header['path'];

            if ($path === 'package.json') {
                return false; // already read
            }
            if ($path === 'database.sql') {
                if ($skip_db) {
                    return false;
                }
                $sql_tmp = wp_tempnam('paio-restore-db');
                return $sql_tmp;
            }
            if (strpos($path, 'wp-content/') !== 0) {
                return false; // ignore anything outside wp-content
            }
            if ($skip_files) {
                return false;
            }
            $inner = substr($path, strlen('wp-content/'));
            if (PAIO_Security::should_skip($inner)) {
                return false;
            }
            $dest = PAIO_Security::safe_join($content_root, $inner);
            if ($dest === false) {
                // Refuse the whole import on a hostile path rather than silently skipping.
                throw new RuntimeException('Unsafe path in archive, aborting: ' . $path);
            }

            $base = strtolower(basename($inner));
            if ($base === '.user.ini' || $base === 'php.ini') {
                $refused[] = array($path, 'PHP ini override');
                return false;
            }
            if ($base === '.htaccess') {
                if ((int) $header['size'] > 262144) {
                    $refused[] = array($path, '.htaccess larger than 256 KB');
                    return false;
                }
                $tmp = wp_tempnam('paio-htaccess');
                $htaccess[] = array($tmp, $dest, $path);
                return $tmp;
            }
            if (PAIO_Security::is_exec($inner)) {
                $zone = PAIO_Security::code_zone($inner);
                if ($zone === false && !$php_anywhere) {
                    $refused[] = array($path, 'executable file outside plugins/themes/mu-plugins/languages');
                    return false;
                }
                if ($zone === 'dropin') {
                    $dropins[] = $path;
                }
            }
            $files_written++;
            return $dest;
        });
        $failed = $reader->failed;
        $reader->close();

        // .htaccess files: restored only if they do nothing but restrict.
        foreach ($htaccess as $h) {
            list($tmp, $dest, $path) = $h;
            $problem = PAIO_Security::htaccess_problem((string) @file_get_contents($tmp));
            if ($problem !== null) {
                $refused[] = array($path, '.htaccess directive: ' . substr($problem, 0, 120));
                @unlink($tmp);
                continue;
            }
            if (is_link($dest)) {
                @unlink($dest);
            }
            if (!is_dir(dirname($dest))) {
                wp_mkdir_p(dirname($dest));
            }
            if (@copy($tmp, $dest)) {
                $files_written++;
            } else {
                $failed[] = $dest;
            }
            @unlink($tmp);
        }

        // Pass 3: load the DB.
        $queries = 0;
        $db_errors = array();
        if (!$skip_db && $sql_tmp) {
            // The storage token lives in wp_options, so the dump would replace it with the source
            // site's and every archive already stored here would vanish from the list.
            $token = get_option('paio_storage_token');
            $res = PAIO_Database::import($sql_tmp, $manifest);
            $queries = $res['queries'];
            $db_errors = $res['errors'];
            @unlink($sql_tmp);
            wp_cache_flush();
            if ($token) {
                update_option('paio_storage_token', $token, false);
            }
            if (function_exists('flush_rewrite_rules')) {
                @flush_rewrite_rules(false);
            }
        }

        return array(
            'files'     => $files_written - count($failed),
            'failed'    => $failed,
            'refused'   => $refused,
            'dropins'   => $dropins,
            'queries'   => $queries,
            'db_errors' => $db_errors,
            'from'      => isset($manifest['siteurl']) ? $manifest['siteurl'] : '',
            'manifest'  => $manifest,
        );
    }

    /** Copies database.sql out of the archive to a temp file (null if the archive has none). */
    private static function extract_sql($archive_path)
    {
        $tmp = null;
        $reader = new PAIO_Archive_Reader();
        $reader->open($archive_path);
        $reader->each(function ($header) use (&$tmp) {
            if ($header['path'] === 'database.sql') {
                $tmp = wp_tempnam('paio-check-db');
                return $tmp;
            }
            return false;
        });
        $reader->close();
        return $tmp;
    }
}
