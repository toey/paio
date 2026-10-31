<?php
/**
 * Database export/import using $wpdb only — no mysqldump, no proc_open (both are blocked
 * by snuffleupagus on this fleet). Export streams a .sql file; import replays it and runs
 * a serialization-safe search/replace for the old site URL and table prefix.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Database
{
    /** Dump every table for the current site's prefix into $sql_path. Returns table count. */
    public static function export($sql_path)
    {
        global $wpdb;
        $fh = fopen($sql_path, 'wb');
        if (!$fh) {
            throw new RuntimeException('Cannot write DB dump: ' . $sql_path);
        }

        fwrite($fh, "-- PAIO database export\n");
        fwrite($fh, '-- prefix: ' . $wpdb->prefix . "\n");
        fwrite($fh, "SET SESSION sql_mode='';\nSET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n");

        $tables = self::site_tables();
        foreach ($tables as $table) {
            $create = $wpdb->get_row('SHOW CREATE TABLE `' . $table . '`', ARRAY_N);
            if (!$create || !isset($create[1])) {
                continue;
            }
            fwrite($fh, "DROP TABLE IF EXISTS `$table`;\n");
            fwrite($fh, $create[1] . ";\n");

            // Stream rows in batches so a big table never loads entirely into memory.
            $offset = 0;
            $batch = 500;
            do {
                $rows = $wpdb->get_results(
                    $wpdb->prepare('SELECT * FROM `' . $table . '` LIMIT %d OFFSET %d', $batch, $offset),
                    ARRAY_A
                );
                if ($rows) {
                    foreach ($rows as $row) {
                        fwrite($fh, self::insert_sql($table, $row) . "\n");
                    }
                    $offset += count($rows);
                }
            } while ($rows && count($rows) === $batch);
            fwrite($fh, "\n");
        }

        fwrite($fh, "SET FOREIGN_KEY_CHECKS=1;\n");
        fclose($fh);
        return count($tables);
    }

    /** Tables that belong to this site (current prefix, incl. multisite blog tables). */
    private static function site_tables()
    {
        global $wpdb;
        $like = $wpdb->esc_like($wpdb->prefix) . '%';
        $rows = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $like));
        return $rows ? $rows : array();
    }

    private static function insert_sql($table, $row)
    {
        global $wpdb;
        $cols = array();
        $vals = array();
        foreach ($row as $col => $val) {
            $cols[] = '`' . str_replace('`', '', $col) . '`';
            if ($val === null) {
                $vals[] = 'NULL';
            } elseif ($val === '') {
                $vals[] = "''";
            } elseif (!preg_match('//u', $val)) {
                // Non-UTF-8 (binary/BLOB) data: emit a hex literal so bytes survive exactly,
                // independent of the connection charset. This is what mysqldump does.
                $vals[] = '0x' . bin2hex($val);
            } else {
                // $wpdb->_real_escape on the live connection; wrap in quotes. Since WP 4.8.3 it
                // also swaps every "%" for this request's random placeholder token, which no other
                // request recognises: put the "%" back, or the import stores the token literally.
                $vals[] = "'" . $wpdb->remove_placeholder_escape($wpdb->_real_escape($val)) . "'";
            }
        }
        return 'INSERT INTO `' . $table . '` (' . implode(',', $cols) . ') VALUES (' . implode(',', $vals) . ');';
    }

    /**
     * Import a .sql dump, rewriting the source prefix to this site's prefix and the source
     * site URL to this site's URL (serialization-safe). $source is the manifest array.
     * Statements are executed one at a time via $wpdb::query.
     */
    public static function import($sql_path, array $source)
    {
        global $wpdb;

        $src_prefix = isset($source['prefix']) ? $source['prefix'] : $wpdb->prefix;
        $dst_prefix = $wpdb->prefix;
        $src_url    = isset($source['siteurl']) ? untrailingslashit($source['siteurl']) : '';
        $dst_url    = untrailingslashit(site_url());
        $src_home   = isset($source['home']) ? untrailingslashit($source['home']) : '';
        $dst_home   = untrailingslashit(home_url());

        $fh = fopen($sql_path, 'rb');
        if (!$fh) {
            throw new RuntimeException('Cannot read DB dump.');
        }

        $buffer = '';
        $count = 0;
        $token = null;   // a 0.1.1 dump's leaked placeholder token (one per export), restored to "%"
        while (!feof($fh)) {
            $line = fgets($fh);
            if ($line === false) {
                break;
            }
            $trim = ltrim($line);
            if ($trim === '' || substr($trim, 0, 2) === '--') {
                continue;
            }
            $buffer .= $line;
            // A statement ends at a line finishing with ";". Good enough for our own dumps
            // because every value is on one INSERT line (no embedded newlines mid-statement
            // except inside quoted data, which _real_escape turned into \n sequences).
            if (preg_match('/;\s*$/', rtrim($line))) {
                $stmt = trim($buffer);
                $buffer = '';
                if ($stmt === '') {
                    continue;
                }
                if ($src_prefix !== $dst_prefix) {
                    $stmt = self::rewrite_prefix($stmt, $src_prefix, $dst_prefix);
                }
                if ($token === null && preg_match('/\{[0-9a-f]{64}\}/', $stmt, $m)) {
                    $token = $m[0];
                }
                if ($token !== null) {
                    $stmt = str_replace($token, '%', $stmt);
                }
                $wpdb->query($stmt);
                $count++;
            }
        }
        fclose($fh);

        // After load, fix URLs across the DB (handles serialized data correctly).
        if ($src_url && $src_url !== $dst_url) {
            self::search_replace($src_url, $dst_url);
        }
        if ($src_home && $src_home !== $dst_home && $src_home !== $src_url) {
            self::search_replace($src_home, $dst_home);
        }
        // Force the canonical options to this site regardless of what the dump carried.
        update_option('siteurl', $dst_url);
        update_option('home', $dst_home);

        return $count;
    }

    /** Rewrite `src_prefix...` table identifiers to the destination prefix (backtick-quoted only). */
    private static function rewrite_prefix($stmt, $src, $dst)
    {
        return preg_replace_callback(
            '/`' . preg_quote($src, '/') . '([0-9a-zA-Z_]*)`/',
            function ($m) use ($dst) {
                return '`' . $dst . $m[1] . '`';
            },
            $stmt
        );
    }

    /**
     * Serialization-safe search/replace across all site tables' text columns.
     * Walks each row, applies a recursive replace that re-counts serialized string lengths.
     */
    public static function search_replace($search, $replace)
    {
        global $wpdb;
        if ($search === '' || $search === $replace) {
            return 0;
        }
        $changed = 0;
        foreach (self::site_tables() as $table) {
            $cols = $wpdb->get_results('SHOW COLUMNS FROM `' . $table . '`', ARRAY_A);
            if (!$cols) {
                continue;
            }
            $pk = null;
            $text_cols = array();
            foreach ($cols as $c) {
                if (isset($c['Key']) && $c['Key'] === 'PRI' && $pk === null) {
                    $pk = $c['Field'];
                }
                if (preg_match('/char|text|blob|json|enum/i', $c['Type'])) {
                    $text_cols[] = $c['Field'];
                }
            }
            if (!$pk || !$text_cols) {
                continue;
            }
            $offset = 0;
            $batch = 500;
            do {
                $rows = $wpdb->get_results(
                    $wpdb->prepare('SELECT * FROM `' . $table . '` LIMIT %d OFFSET %d', $batch, $offset),
                    ARRAY_A
                );
                if ($rows) {
                    foreach ($rows as $row) {
                        $update = array();
                        foreach ($text_cols as $col) {
                            if (!isset($row[$col]) || strpos($row[$col], $search) === false) {
                                continue;
                            }
                            $new = self::recursive_replace($search, $replace, $row[$col]);
                            if ($new !== $row[$col]) {
                                $update[$col] = $new;
                            }
                        }
                        if ($update) {
                            $wpdb->update($table, $update, array($pk => $row[$pk]));
                            $changed++;
                        }
                    }
                    $offset += count($rows);
                }
            } while ($rows && count($rows) === $batch);
        }
        return $changed;
    }

    /** Unserialize if possible, replace within, re-serialize (keeps string lengths valid). */
    private static function recursive_replace($search, $replace, $data)
    {
        if (is_string($data)) {
            $un = @unserialize($data);
            if ($un !== false || $data === 'b:0;') {
                return serialize(self::walk($search, $replace, $un));
            }
            return str_replace($search, $replace, $data);
        }
        return self::walk($search, $replace, $data);
    }

    private static function walk($search, $replace, $value)
    {
        if (is_string($value)) {
            return str_replace($search, $replace, $value);
        }
        if (is_array($value)) {
            $out = array();
            foreach ($value as $k => $v) {
                $out[is_string($k) ? str_replace($search, $replace, $k) : $k] = self::walk($search, $replace, $v);
            }
            return $out;
        }
        if (is_object($value)) {
            foreach (get_object_vars($value) as $k => $v) {
                $value->$k = self::walk($search, $replace, $v);
            }
            return $value;
        }
        return $value;
    }
}
