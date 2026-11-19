<?php
/**
 * Storage protection + path-safety helpers. These are the guardrails that keep a
 * migration tool from becoming the next RCE: a locked-down backup directory and a
 * single choke-point for validating every path that comes out of an archive.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Security
{
    /**
     * Absolute path to the backup storage directory. Lives under wp-content in a
     * random-token subdirectory so its contents can't be guessed from the web, and is
     * made non-browsable / non-executable by ensure_storage().
     */
    public static function storage_dir()
    {
        $base = WP_CONTENT_DIR . '/paio-backups';
        $token = get_option('paio_storage_token');
        if (!$token || !preg_match('/^[a-f0-9]{32}$/', $token)) {
            $token = md5(wp_generate_password(64, true, true) . microtime(true));
            update_option('paio_storage_token', $token, false);
        }
        return $base . '/' . $token;
    }

    /** Create the storage dir and drop in deny-all guards for Apache, IIS and a dir-listing block. */
    public static function ensure_storage()
    {
        $dir = self::storage_dir();
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }

        $htaccess = WP_CONTENT_DIR . '/paio-backups/.htaccess';
        if (!file_exists($htaccess)) {
            // Deny all web access AND disable PHP handlers, so a dropped .php can't execute.
            // NOTE: on hosts where a global <Location "/"> grant overrides .htaccess Require
            // rules, this deny is clobbered -- the random-token subdir is the primary defense,
            // and operators should add a server-side rule for /paio-backups/ (see readme.txt,
            // "Server-side protection").
            // No php_flag line: it is invalid under PHP-FPM and aborts the whole .htaccess.
            $rules = "Require all denied\n"
                   . "<IfModule !mod_authz_core.c>\n  Order allow,deny\n  Deny from all\n</IfModule>\n"
                   . "<FilesMatch \"\\.(php|php5|php7|php8|phtml|phar)$\">\n  SetHandler none\n  ForceType text/plain\n</FilesMatch>\n";
            @file_put_contents($htaccess, $rules);
        }

        $webconfig = WP_CONTENT_DIR . '/paio-backups/web.config';
        if (!file_exists($webconfig)) {
            @file_put_contents($webconfig,
                "<?xml version=\"1.0\"?>\n<configuration><system.webServer>"
                . "<authorization><deny users=\"*\"/></authorization>"
                . "</system.webServer></configuration>\n");
        }

        foreach (array(WP_CONTENT_DIR . '/paio-backups/index.php', $dir . '/index.php') as $guard) {
            if (!file_exists($guard)) {
                @file_put_contents($guard, "<?php // Silence is golden.\n");
            }
        }
        return $dir;
    }

    /**
     * Validate a relative path coming out of an archive and resolve it under $base.
     * Rejects absolute paths, Windows drive/UNC paths, null bytes, and any traversal.
     * Returns the safe absolute path, or false if the entry must be refused.
     */
    public static function safe_join($base, $rel)
    {
        if (!is_string($rel) || $rel === '' || strlen($rel) > 4096) {
            return false;
        }
        if (strpos($rel, "\0") !== false) {
            return false;
        }
        // Normalize separators, reject absolute / drive / UNC forms.
        $rel = str_replace('\\', '/', $rel);
        if ($rel[0] === '/' || preg_match('#^[a-zA-Z]:#', $rel)) {
            return false;
        }
        $parts = array();
        foreach (explode('/', $rel) as $seg) {
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                return false; // never allow climbing out
            }
            $parts[] = $seg;
        }
        if (!$parts) {
            return false;
        }
        $base = rtrim($base, '/');
        $full = $base . '/' . implode('/', $parts);
        // Final belt-and-suspenders: the resolved path must stay under $base.
        if (strpos($full, $base . '/') !== 0) {
            return false;
        }
        return $full;
    }

    /**
     * Extensions the web server or a CGI handler could execute. Files with these may only be
     * restored into the code areas of wp-content (see code_zone()).
     */
    public static function is_exec($rel)
    {
        return (bool) preg_match('/\.(php\d?|phtml|pht|phps|phar|inc|cgi|pl|py|sh|fbi|shtml)$/i', $rel);
    }

    /** Server/PHP config files an archive must not drop unchecked (handler and ini overrides). */
    public static function is_server_config($rel)
    {
        $b = strtolower(basename($rel));
        return $b === '.htaccess' || $b === '.user.ini' || $b === 'php.ini';
    }

    /** WordPress drop-ins: PHP that loads before plugins on every request (also where the SC_DB recreator hid). */
    public static function dropins()
    {
        return array(
            'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php',
            'object-cache.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php',
            'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php',
        );
    }

    /**
     * Where executable files may land: plugins/themes/mu-plugins/languages, plus the drop-ins and
     * the index.php guard at the wp-content root. Returns 'code', 'dropin' or false. Before 0.1.5
     * an archive could put PHP anywhere under wp-content, uploads/ included, and an import from the
     * GUI also walked straight past DISALLOW_FILE_MODS.
     */
    public static function code_zone($inner)
    {
        if (preg_match('#^(plugins|themes|mu-plugins|languages)/#', $inner)) {
            return 'code';
        }
        if (strpos($inner, '/') === false) {
            if ($inner === 'index.php') {
                return 'code';
            }
            if (in_array($inner, self::dropins(), true)) {
                return 'dropin';
            }
        }
        return false;
    }

    /**
     * Returns null when an .htaccess only restricts access, else the first offending line. Refused:
     * anything that maps a handler or type to PHP/CGI/SSI, turns on ExecCGI/Includes, or changes
     * PHP settings - the "make .jpg executable" and "disable_functions = none" tricks seen on the
     * fleet. Protective forms (SetHandler none, ForceType text/plain, Options -ExecCGI) pass.
     */
    public static function htaccess_problem($content)
    {
        foreach (preg_split('/\r\n|\r|\n/', (string) $content) as $line) {
            $l = trim($line);
            if ($l === '' || $l[0] === '#') {
                continue;
            }
            if (!preg_match('/^<?\s*([A-Za-z_]+)\b(.*)$/', $l, $m)) {
                continue;
            }
            $dir = strtolower($m[1]);
            $arg = trim($m[2]);
            if (strpos($dir, 'php_') === 0) {
                return $l;
            }
            if ($dir === 'sethandler') {
                if (!preg_match('/^"?none"?$/i', $arg)) {
                    return $l;
                }
            } elseif ($dir === 'forcetype') {
                if (!preg_match('#^"?(text/plain|application/octet-stream|none)"?$#i', $arg)) {
                    return $l;
                }
            } elseif (in_array($dir, array('addhandler', 'addtype', 'action', 'addoutputfilter', 'setoutputfilter',
                                            'addinputfilter', 'setinputfilter', 'setenv', 'setenvif'), true)) {
                if (preg_match('/php|x-httpd|cgi|server-parsed|includes|auto_(pre|ap)pend/i', $arg)) {
                    return $l;
                }
            } elseif ($dir === 'options') {
                if (preg_match('/(?<![-\w])(ExecCGI|Includes|IncludesNOEXEC|All)\b/i', $arg)) {
                    return $l;
                }
            }
        }
        return null;
    }

    /** True if the GUI request is allowed: capability + valid nonce for $action. */
    public static function check_ajax($action)
    {
        if (!is_user_logged_in() || !current_user_can(PAIO_CAP)) {
            wp_send_json_error(array('message' => 'Insufficient permissions.'), 403);
        }
        if (!check_ajax_referer('paio_' . $action, 'nonce', false)) {
            wp_send_json_error(array('message' => 'Invalid or expired security token.'), 403);
        }
    }

    /**
     * Decide whether a wp-content file should be included in an export.
     * Skips the backup storage itself, caches, and the usual throwaway dirs.
     */
    public static function should_skip($rel)
    {
        $skip_prefixes = array(
            'paio-backups/',
            'plugins/paio/',          // never migrate/overwrite this plugin itself
            'mu-plugins/paio',        // (any mu-loader variant)
            'cache/',
            'wp-rocket-config/',
            'uploads/cache/',
            'uploads/wp-migrate-db/',
            'ai1wm-backups/',
            'updraft/',
            'backup/',
            'backups/',
        );
        foreach ($skip_prefixes as $p) {
            if (strpos($rel, $p) === 0) {
                return true;
            }
        }
        $base = basename($rel);
        if ($base === '.DS_Store' || substr($base, 0, 2) === '._' || substr($base, -4) === '.log') {
            return true; // macOS junk / AppleDouble / logs
        }
        return false;
    }
}
