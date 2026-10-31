<?php
/**
 * wp-admin GUI. Every AJAX handler is gated by PAIO_Security::check_ajax() which enforces
 * BOTH a logged-in manage_options user AND a per-action nonce. There is deliberately no
 * wp_ajax_nopriv_* registration anywhere in PAIO.
 *
 * For very large sites use WP-CLI instead — a single web request can hit PHP max_execution_time.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Admin
{
    public static function init()
    {
        add_action('admin_menu', array(__CLASS__, 'menu'));
        add_action('admin_enqueue_scripts', array(__CLASS__, 'assets'));

        // Authenticated AJAX only. No nopriv counterparts — by design.
        add_action('wp_ajax_paio_export', array(__CLASS__, 'ajax_export'));
        add_action('wp_ajax_paio_import', array(__CLASS__, 'ajax_import'));
        add_action('wp_ajax_paio_upload', array(__CLASS__, 'ajax_upload'));
        add_action('wp_ajax_paio_list',   array(__CLASS__, 'ajax_list'));
        add_action('wp_ajax_paio_download', array(__CLASS__, 'ajax_download'));
        add_action('wp_ajax_paio_delete', array(__CLASS__, 'ajax_delete'));
    }

    public static function menu()
    {
        add_management_page(
            'PAIO Migration', 'PAIO Migration', PAIO_CAP, 'paio', array(__CLASS__, 'page')
        );
    }

    public static function assets($hook)
    {
        if ($hook !== 'tools_page_paio') {
            return;
        }
        wp_enqueue_script('paio', PAIO_URL . 'admin/js/paio.js', array('jquery'), PAIO_VERSION, true);
        wp_localize_script('paio', 'PAIO', array(
            'ajax'   => admin_url('admin-ajax.php'),
            'nonces' => array(
                'export'   => wp_create_nonce('paio_export'),
                'import'   => wp_create_nonce('paio_import'),
                'upload'   => wp_create_nonce('paio_upload'),
                'list'     => wp_create_nonce('paio_list'),
                'download' => wp_create_nonce('paio_download'),
                'delete'   => wp_create_nonce('paio_delete'),
            ),
        ));
    }

    public static function page()
    {
        if (!current_user_can(PAIO_CAP)) {
            wp_die('Insufficient permissions.');
        }
        require PAIO_DIR . 'admin/page.php';
    }

    // ---- AJAX handlers -----------------------------------------------------

    public static function ajax_export()
    {
        PAIO_Security::check_ajax('export');
        try {
            $res = PAIO_Exporter::run();
            wp_send_json_success(array(
                'file'  => basename($res['path']),
                'files' => $res['files'],
                'tables' => $res['tables'],
                'size'  => size_format($res['bytes']),
            ));
        } catch (Throwable $e) {
            wp_send_json_error(array('message' => $e->getMessage()), 500);
        }
    }

    /** Receive an uploaded .paio file into the protected storage dir. */
    public static function ajax_upload()
    {
        PAIO_Security::check_ajax('upload');
        if (empty($_FILES['archive']) || !isset($_FILES['archive']['tmp_name'])) {
            wp_send_json_error(array('message' => 'No file received.'), 400);
        }
        $f = $_FILES['archive'];
        if (!empty($f['error'])) {
            wp_send_json_error(array('message' => 'Upload error code ' . (int) $f['error']), 400);
        }
        if (!is_uploaded_file($f['tmp_name'])) {
            wp_send_json_error(array('message' => 'Invalid upload.'), 400);
        }
        $name = sanitize_file_name(basename($f['name']));
        if (strtolower(pathinfo($name, PATHINFO_EXTENSION)) !== PAIO_ARCHIVE_EXT) {
            wp_send_json_error(array('message' => 'Only .' . PAIO_ARCHIVE_EXT . ' archives are accepted.'), 400);
        }
        // Verify the magic before trusting it.
        $fh = fopen($f['tmp_name'], 'rb');
        $magic = $fh ? rtrim((string) fgets($fh), "\r\n") : '';
        if ($fh) { fclose($fh); }
        if ($magic !== PAIO_ARCHIVE_MAGIC) {
            wp_send_json_error(array('message' => 'File is not a valid PAIO archive.'), 400);
        }
        $dir = PAIO_Security::ensure_storage();
        $dest = $dir . '/' . $name;
        if (!move_uploaded_file($f['tmp_name'], $dest)) {
            wp_send_json_error(array('message' => 'Could not store the uploaded file.'), 500);
        }
        wp_send_json_success(array('file' => $name, 'size' => size_format(filesize($dest))));
    }

    public static function ajax_import()
    {
        PAIO_Security::check_ajax('import');
        $file = isset($_POST['file']) ? sanitize_file_name(wp_unslash($_POST['file'])) : '';
        $path = self::resolve($file);
        if (!$path) {
            wp_send_json_error(array('message' => 'Archive not found.'), 404);
        }
        try {
            $res = PAIO_Importer::run($path, array(
                'skip_db'    => !empty($_POST['skip_db']),
                'skip_files' => !empty($_POST['skip_files']),
            ));
            wp_send_json_success(array(
                'files'   => $res['files'],
                'failed'  => count($res['failed']),
                'queries' => $res['queries'],
                'from'    => $res['from'],
            ));
        } catch (Throwable $e) {
            wp_send_json_error(array('message' => $e->getMessage()), 500);
        }
    }

    public static function ajax_list()
    {
        PAIO_Security::check_ajax('list');
        $dir = PAIO_Security::ensure_storage();
        $items = glob($dir . '/*.' . PAIO_ARCHIVE_EXT) ?: array();
        $out = array();
        foreach ($items as $f) {
            $out[] = array(
                'file' => basename($f),
                'size' => size_format(filesize($f)),
                'date' => gmdate('Y-m-d H:i', filemtime($f)),
            );
        }
        usort($out, function ($a, $b) { return strcmp($b['date'], $a['date']); });
        wp_send_json_success($out);
    }

    /**
     * Stream a stored archive to the browser for download. Archives are often 1 GB+, so: no output
     * buffering, no time limit, a chunked fread loop (fpassthru/readfile are in the fleet's
     * disable_functions), and single HTTP Range support so an interrupted download can resume.
     */
    public static function ajax_download()
    {
        PAIO_Security::check_ajax('download');
        $file = isset($_GET['file']) ? sanitize_file_name(wp_unslash($_GET['file'])) : '';
        $path = self::resolve($file);
        if (!$path) {
            wp_die('Not found', '', array('response' => 404));
        }
        $size = (int) filesize($path);
        $fh = fopen($path, 'rb');
        if (!$fh) {
            wp_die('Cannot read the archive.', '', array('response' => 500));
        }
        if (function_exists('set_time_limit')) {
            @set_time_limit(0);
        }
        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        $start = 0;
        $end = $size - 1;
        $status = 200;
        $range = isset($_SERVER['HTTP_RANGE']) ? trim((string) $_SERVER['HTTP_RANGE']) : '';
        if ($range !== '' && preg_match('/^bytes=(\d*)-(\d*)$/', $range, $m) && ($m[1] !== '' || $m[2] !== '')) {
            if ($m[1] === '') {                       // "bytes=-N": the last N bytes
                $start = max(0, $size - (int) $m[2]);
            } else {
                $start = (int) $m[1];
                if ($m[2] !== '') {
                    $end = min($end, (int) $m[2]);
                }
            }
            if ($start > $end || $start >= $size) {
                fclose($fh);
                status_header(416);
                header('Content-Range: bytes */' . $size);
                exit;
            }
            $status = 206;
        }

        nocache_headers();
        // no-transform: the CDN/WAF in front must not gzip the archive either (keeps the exact
        // Content-Length the browser needs for size/progress, and byte ranges for resume).
        header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0, private, no-transform');
        status_header($status);
        // A type of its own (not octet-stream): the WAF/CDN in front gzips octet-stream on the fly,
        // which made a 1.3 GB download ~2.5x slower; attachment + .paio name still save as a file.
        header('Content-Type: application/vnd.paio');
        header('Content-Disposition: attachment; filename="' . $file . '"');
        header('X-Content-Type-Options: nosniff');
        header('Accept-Ranges: bytes');
        header('Content-Length: ' . ($end - $start + 1));
        if ($status === 206) {
            header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
        }
        if ($start > 0) {
            fseek($fh, $start);
        }
        $left = $end - $start + 1;
        while ($left > 0 && !feof($fh) && !connection_aborted()) {
            $buf = fread($fh, (int) min(1048576, $left));
            if ($buf === false || $buf === '') {
                break;
            }
            echo $buf;
            $left -= strlen($buf);
            flush();
        }
        fclose($fh);
        exit;
    }

    public static function ajax_delete()
    {
        PAIO_Security::check_ajax('delete');
        $file = isset($_POST['file']) ? sanitize_file_name(wp_unslash($_POST['file'])) : '';
        $path = self::resolve($file);
        if (!$path) {
            wp_send_json_error(array('message' => 'Not found.'), 404);
        }
        @unlink($path);
        wp_send_json_success(array('file' => $file));
    }

    /** Resolve a user-supplied filename to a real path inside the storage dir, or false. */
    private static function resolve($file)
    {
        if ($file === '' || strtolower(pathinfo($file, PATHINFO_EXTENSION)) !== PAIO_ARCHIVE_EXT) {
            return false;
        }
        $dir = PAIO_Security::ensure_storage();
        $path = $dir . '/' . basename($file);
        return is_file($path) ? $path : false;
    }
}
