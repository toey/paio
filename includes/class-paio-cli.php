<?php
/**
 * WP-CLI front-end. Runs inside WP, so it shares the exact engine the GUI uses.
 * This is the safest way to migrate large sites (no web timeout, no web attack surface).
 *
 *   wp paio export [<file>]
 *   wp paio import <file> [--skip-db] [--skip-files] [--allow-php-anywhere] [--yes]
 *   wp paio list
 */

if (!defined('ABSPATH') || !defined('WP_CLI') || !WP_CLI) {
    return;
}

class PAIO_CLI
{
    /**
     * Export this site to a .paio archive.
     *
     * ## OPTIONS
     * [<file>]
     * : Destination path. Default: an auto-named file in the protected storage dir.
     *
     * @when after_wp_load
     */
    public function export($args, $assoc)
    {
        $dest = isset($args[0]) ? $args[0] : null;
        WP_CLI::log('Exporting ' . home_url() . ' ...');
        $res = PAIO_Exporter::run($dest);
        if (!empty($res['links_skipped'])) {
            WP_CLI::warning(sprintf('%d symlink(s) were not followed and are NOT in the archive:', count($res['links_skipped'])));
            foreach (array_slice($res['links_skipped'], 0, 20) as $l) {
                WP_CLI::log('  - ' . $l);
            }
        }
        WP_CLI::success(sprintf(
            'Exported %d files + %d tables -> %s (%s)',
            $res['files'], $res['tables'], $res['path'], size_format($res['bytes'])
        ));
    }

    /**
     * Import a .paio archive into this site (overwrites wp-content + database).
     *
     * ## OPTIONS
     * <file>
     * : Path to the .paio archive.
     *
     * [--skip-db]
     * : Restore files only, leave the database untouched.
     *
     * [--skip-files]
     * : Restore the database only, leave wp-content untouched.
     *
     * [--allow-php-anywhere]
     * : Also restore executable files (php, phtml, phar, inc...) outside plugins/, themes/,
     * mu-plugins/ and languages/ - e.g. under uploads/. Off by default: that is where webshells
     * live. Use only for an archive you have checked.
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * @when after_wp_load
     */
    public function import($args, $assoc)
    {
        if (empty($args[0])) {
            WP_CLI::error('Specify the archive path.');
        }
        $file = $args[0];
        WP_CLI::warning('This overwrites the current site at ' . home_url());
        WP_CLI::confirm('Proceed with import from ' . basename($file) . '?', $assoc);

        $res = PAIO_Importer::run($file, array(
            'skip_db'    => (bool) WP_CLI\Utils\get_flag_value($assoc, 'skip-db', false),
            'skip_files' => (bool) WP_CLI\Utils\get_flag_value($assoc, 'skip-files', false),
            'allow_php_anywhere' => (bool) WP_CLI\Utils\get_flag_value($assoc, 'allow-php-anywhere', false),
            'via'        => 'cli',
        ));
        if (!empty($res['refused'])) {
            WP_CLI::warning(sprintf('%d file(s) refused for safety (not restored):', count($res['refused'])));
            foreach (array_slice($res['refused'], 0, 30) as $r) {
                WP_CLI::log('  - ' . $r[0] . '  [' . $r[1] . ']');
            }
            if (count($res['refused']) > 30) {
                WP_CLI::log('  ... and ' . (count($res['refused']) - 30) . ' more');
            }
        }
        if (!empty($res['dropins'])) {
            WP_CLI::warning('Drop-ins restored (they run before every plugin - check them): ' . implode(', ', $res['dropins']));
        }
        if (!empty($res['db_errors'])) {
            WP_CLI::warning(sprintf('%d database statement(s) failed (first ones shown):', count($res['db_errors'])));
            foreach ($res['db_errors'] as $e) {
                WP_CLI::log('  - ' . $e);
            }
        }
        if (!empty($res['failed'])) {
            WP_CLI::warning(sprintf('%d file(s) could not be written (skipped):', count($res['failed'])));
            foreach (array_slice($res['failed'], 0, 10) as $f) {
                WP_CLI::log('  - ' . $f);
            }
            if (count($res['failed']) > 10) {
                WP_CLI::log('  ... and ' . (count($res['failed']) - 10) . ' more');
            }
        }
        WP_CLI::success(sprintf(
            'Imported %d files + %d statements (source: %s)',
            $res['files'], $res['queries'], $res['from'] ?: 'n/a'
        ));
    }

    /** Shared by the "wp paio list" closure registered below. */
    public static function render_list()
    {
        $dir = PAIO_Security::ensure_storage();
        $items = glob($dir . '/*.' . PAIO_ARCHIVE_EXT);
        if (!$items) {
            WP_CLI::log('No archives in ' . $dir);
            return;
        }
        $rows = array();
        foreach ($items as $f) {
            $rows[] = array('file' => basename($f), 'size' => size_format(filesize($f)), 'modified' => gmdate('Y-m-d H:i', filemtime($f)));
        }
        WP_CLI\Utils\format_items('table', $rows, array('file', 'size', 'modified'));
    }
}

// Register "list" as its own command so it doesn't collide with the reserved method name.
WP_CLI::add_command('paio list', array('PAIO_CLI', 'render_list'));
