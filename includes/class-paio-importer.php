<?php
/**
 * Full-site importer: validates a .paio archive, extracts wp-content (every path confined
 * under WP_CONTENT_DIR), then replays database.sql with URL/prefix rewriting.
 *
 * Safety invariants:
 *   - Reads the manifest first; refuses an archive without a valid PAIO1 magic / package.json.
 *   - Every file path is run through PAIO_Security::safe_join() -> no traversal, no absolute.
 *   - PHP files are allowed ONLY under wp-content (themes/plugins/mu-plugins), never elsewhere,
 *     and the archive can't place anything outside wp-content by construction.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Importer
{
    /**
     * @param string $archive_path  Path to a .paio archive (already stored/uploaded).
     * @param array  $opts          ['skip_db'=>bool, 'skip_files'=>bool]
     * @return array summary
     */
    public static function run($archive_path, array $opts = array())
    {
        @set_time_limit(0);
        if (!is_file($archive_path) || !is_readable($archive_path)) {
            throw new RuntimeException('Archive not found or unreadable.');
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

        $skip_db    = !empty($opts['skip_db']);
        $skip_files = !empty($opts['skip_files']);
        $content_root = WP_CONTENT_DIR;
        $sql_tmp = null;
        $files_written = 0;

        // Pass 2: stream the archive, extract wp-content, capture database.sql to a temp file.
        $reader = new PAIO_Archive_Reader();
        $reader->open($archive_path);
        $reader->each(function ($header) use (&$sql_tmp, $content_root, $skip_db, $skip_files, &$files_written) {
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
            $files_written++;
            return $dest;
        });
        $failed = $reader->failed;
        $reader->close();

        // Pass 3: load the DB.
        $queries = 0;
        if (!$skip_db && $sql_tmp) {
            $queries = PAIO_Database::import($sql_tmp, $manifest);
            @unlink($sql_tmp);
            wp_cache_flush();
            if (function_exists('flush_rewrite_rules')) {
                @flush_rewrite_rules(false);
            }
        }

        return array(
            'files'    => $files_written - count($failed),
            'failed'   => $failed,
            'queries'  => $queries,
            'from'     => isset($manifest['siteurl']) ? $manifest['siteurl'] : '',
            'manifest' => $manifest,
        );
    }
}
