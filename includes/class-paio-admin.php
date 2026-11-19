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
        add_action('wp_ajax_paio_upload_chunk', array(__CLASS__, 'ajax_upload_chunk'));
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
        // Chunk size for browser uploads: well under post_max_size/upload_max_filesize (64 MB here) and
        // under typical CDN/WAF request-body limits. 1 GB+ archives go up as ~8 MB requests.
        $max = (int) wp_max_upload_size();
        $chunk = 8 * 1024 * 1024;
        if ($max > 0 && $chunk > $max - 524288) {
            $chunk = max(1048576, $max - 524288);
        }
        wp_localize_script('paio', 'PAIO', array(
            'ajax'   => admin_url('admin-ajax.php'),
            'chunk'  => $chunk,
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
                'links_skipped' => count($res['links_skipped']),
            ));
        } catch (Throwable $e) {
            wp_send_json_error(array('message' => $e->getMessage()), 500);
        }
    }

    /**
     * Chunked upload (0.1.3): the browser sends the archive in pieces of PAIO.chunk bytes, in order.
     * Each piece is appended to a hidden ".upload-<id>.partial" file in the protected storage dir; the
     * last piece renames it to its .paio name. A retried piece that was already appended is accepted
     * (idempotent), any other offset mismatch answers 409 with the expected offset so the client resumes.
     * Same gates as every PAIO action: manage_options + nonce, archive magic checked on the first piece.
     */
    public static function ajax_upload_chunk()
    {
        PAIO_Security::check_ajax('upload');
        $id = isset($_POST['upload_id']) ? (string) wp_unslash($_POST['upload_id']) : '';
        if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
            wp_send_json_error(array('message' => 'Invalid upload id.'), 400);
        }
        $name = isset($_POST['name']) ? sanitize_file_name(basename(wp_unslash($_POST['name']))) : '';
        if ($name === '' || strtolower(pathinfo($name, PATHINFO_EXTENSION)) !== PAIO_ARCHIVE_EXT) {
            wp_send_json_error(array('message' => 'Only .' . PAIO_ARCHIVE_EXT . ' archives are accepted.'), 400);
        }
        $offset = isset($_POST['offset']) ? (int) $_POST['offset'] : -1;
        $total  = isset($_POST['total']) ? (int) $_POST['total'] : 0;
        $last   = !empty($_POST['last']);
        if ($offset < 0 || $total <= 0 || $offset >= $total) {
            wp_send_json_error(array('message' => 'Invalid chunk offset.'), 400);
        }
        if (empty($_FILES['chunk']) || !empty($_FILES['chunk']['error']) || !is_uploaded_file($_FILES['chunk']['tmp_name'])) {
            $code = isset($_FILES['chunk']['error']) ? (int) $_FILES['chunk']['error'] : 0;
            wp_send_json_error(array('message' => 'Chunk not received (error ' . $code . ').'), 400);
        }
        $tmp = $_FILES['chunk']['tmp_name'];
        $len = (int) filesize($tmp);

        // 0.1.4: the browser sends the SHA-256 of each piece. 2026-11-16 a 1.2 GB upload through the
        // CDN/WAF arrived with the right size but 26 of 154 pieces altered inside, so the archive was
        // unusable. A piece that does not match is refused (422) and the browser resends it.
        $want = isset($_POST['sha256']) ? strtolower((string) wp_unslash($_POST['sha256'])) : '';
        if ($want !== '') {
            if (!preg_match('/^[a-f0-9]{64}$/', $want)) {
                wp_send_json_error(array('message' => 'Invalid chunk checksum.'), 400);
            }
            if (!hash_equals($want, (string) hash_file('sha256', $tmp))) {
                wp_send_json_error(array('message' => 'Piece damaged in transit (checksum mismatch).', 'corrupt' => true), 422);
            }
        }

        $dir  = PAIO_Security::ensure_storage();
        $part = $dir . '/.upload-' . $id . '.partial';

        // Housekeeping: abandoned partial uploads older than 24 h.
        if ($offset === 0) {
            foreach (glob($dir . '/.upload-*.partial') ?: array() as $old) {
                if (is_file($old) && filemtime($old) < time() - DAY_IN_SECONDS) {
                    @unlink($old);
                }
            }
            $fh = fopen($tmp, 'rb');
            $magic = $fh ? rtrim((string) fgets($fh), "\r\n") : '';
            if ($fh) { fclose($fh); }
            if ($magic !== PAIO_ARCHIVE_MAGIC) {
                wp_send_json_error(array('message' => 'File is not a valid PAIO archive.'), 400);
            }
        }

        $out = fopen($part, 'c+b');
        if (!$out || !flock($out, LOCK_EX)) {
            wp_send_json_error(array('message' => 'Could not open the upload buffer.'), 500);
        }
        clearstatcache(true, $part);
        $have = (int) filesize($part);
        if ($offset !== $have) {
            if ($offset + $len === $have) {          // a retry of a piece we already appended
                flock($out, LOCK_UN); fclose($out);
                self::finish_chunk($part, $dir, $name, $have, $total, $last);
            }
            flock($out, LOCK_UN); fclose($out);
            wp_send_json_error(array('message' => 'Out of order chunk.', 'expected' => $have), 409);
        }
        if ($have + $len > $total) {
            flock($out, LOCK_UN); fclose($out);
            wp_send_json_error(array('message' => 'Chunk exceeds the declared size.'), 400);
        }
        $in = fopen($tmp, 'rb');
        fseek($out, $have);
        while ($in && !feof($in)) {
            $buf = fread($in, 1048576);
            if ($buf === false || $buf === '') {
                break;
            }
            if (fwrite($out, $buf) !== strlen($buf)) {
                fclose($in); flock($out, LOCK_UN); fclose($out);
                wp_send_json_error(array('message' => 'Write failed (disk full or quota?).'), 507);
            }
        }
        if ($in) { fclose($in); }
        fflush($out);
        flock($out, LOCK_UN);
        fclose($out);
        clearstatcache(true, $part);
        self::finish_chunk($part, $dir, $name, (int) filesize($part), $total, $last);
    }

    /** Reply for a stored chunk; on the last one, move the completed buffer to its .paio name. */
    private static function finish_chunk($part, $dir, $name, $have, $total, $last)
    {
        if (!$last) {
            wp_send_json_success(array('received' => $have));
        }
        if ($have !== $total) {
            wp_send_json_error(array('message' => 'Upload incomplete (' . $have . ' of ' . $total . ' bytes).', 'expected' => $have), 409);
        }
        // Whole-archive structure check before it is listed as importable. Every piece was already
        // checksum-verified, so a failure here means the file was damaged before the upload began.
        $bad = PAIO_Archive_Reader::verify($part);
        if ($bad !== null) {
            @unlink($part);
            wp_send_json_error(array('message' => 'The archive is damaged: ' . $bad . '. The file on your computer is already corrupt. Download it again (and check its SHA-256), then upload again.'), 422);
        }
        $base = substr($name, 0, -strlen('.' . PAIO_ARCHIVE_EXT));
        $dest = $dir . '/' . $name;
        for ($i = 1; file_exists($dest) && $i < 1000; $i++) {
            $dest = $dir . '/' . $base . '-' . $i . '.' . PAIO_ARCHIVE_EXT;
        }
        if (!rename($part, $dest)) {
            wp_send_json_error(array('message' => 'Could not store the uploaded file.'), 500);
        }
        wp_send_json_success(array('file' => basename($dest), 'size' => size_format(filesize($dest)), 'done' => true));
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
                'via'        => 'gui',
            ));
            $refused = array();
            foreach (array_slice($res['refused'], 0, 20) as $r) {
                $refused[] = $r[0] . ' (' . $r[1] . ')';
            }
            wp_send_json_success(array(
                'files'     => $res['files'],
                'failed'    => count($res['failed']),
                'refused'   => count($res['refused']),
                'refused_list' => $refused,
                'dropins'   => $res['dropins'],
                'queries'   => $res['queries'],
                'db_errors' => $res['db_errors'],
                'from'      => $res['from'],
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
