<?php
/**
 * Full-site exporter: builds a .paio archive containing package.json (manifest),
 * database.sql (full DB dump) and every file under wp-content (minus caches/backups).
 * Shared by both the WP-CLI command and the wp-admin GUI.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Exporter
{
    /**
     * @param string|null $dest_path  Where to write the archive. Null => auto name in storage.
     * @return array ['path'=>.., 'files'=>N, 'tables'=>N, 'bytes'=>N]
     */
    public static function run($dest_path = null)
    {
        global $wpdb;
        @set_time_limit(0);

        if ($dest_path === null) {
            $dir = PAIO_Security::ensure_storage();
            $name = sanitize_file_name(
                parse_url(home_url(), PHP_URL_HOST) . '-' . gmdate('Ymd-His') . '.' . PAIO_ARCHIVE_EXT
            );
            $dest_path = $dir . '/' . $name;
        }

        // 1. DB dump to a temp file.
        $sql_tmp = wp_tempnam('paio-db');
        $tables = PAIO_Database::export($sql_tmp);

        // 2. Manifest.
        $manifest = array(
            'generator'   => 'PAIO ' . PAIO_VERSION,
            'created'     => gmdate('c'),
            'siteurl'     => site_url(),
            'home'        => home_url(),
            'prefix'      => $wpdb->prefix,
            'wp_version'  => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'charset'     => defined('DB_CHARSET') ? DB_CHARSET : '',
            'multisite'   => is_multisite() ? 1 : 0,
            'tables'      => $tables,
        );

        // 3. Write archive.
        $writer = new PAIO_Archive_Writer();
        $writer->open($dest_path);
        $writer->add_string('package.json', wp_json_encode($manifest));
        $writer->add_file($sql_tmp, 'database.sql');
        @unlink($sql_tmp);

        $links = array();
        $files = self::add_wp_content($writer, $links);
        $writer->close();

        return array(
            'path'   => $dest_path,
            'files'  => $files,
            'tables' => $tables,
            'bytes'  => filesize($dest_path),
            'links_skipped' => $links,
        );
    }

    /**
     * Recursively add wp-content, skipping the storage dir and caches. Returns file count.
     * Symlinks are not followed (0.1.5): following them could pull files from outside
     * wp-content - another account's tree, or /etc - into an archive, or loop forever. Skipped
     * links are returned in $links so the operator can copy those targets separately.
     */
    private static function add_wp_content(PAIO_Archive_Writer $writer, array &$links)
    {
        $root = WP_CONTENT_DIR;
        $count = 0;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($it as $file) {
            $abs = $file->getPathname();
            $rel = 'wp-content/' . ltrim(str_replace('\\', '/', substr($abs, strlen($root))), '/');
            $inner = substr($rel, strlen('wp-content/'));
            if ($file->isLink()) {
                if (!PAIO_Security::should_skip($inner)) {
                    $links[] = $rel;
                }
                continue;
            }
            if (!$file->isFile()) {
                continue;
            }
            if (PAIO_Security::should_skip($inner)) {
                continue;
            }
            $writer->add_file($abs, $rel);
            $count++;
        }
        return $count;
    }
}
