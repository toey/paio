<?php
/**
 * Database export/import using $wpdb only — no mysqldump, no proc_open (both are blocked
 * by snuffleupagus on this fleet). Export streams a .sql file; import replays it and runs
 * a serialization-safe search/replace for the old site URL and table prefix.
 *
 * 0.1.5: an imported dump is untrusted. Before anything runs, every statement must be one of
 * the shapes our own exporter writes (SET / DROP TABLE IF EXISTS / CREATE TABLE / INSERT INTO)
 * on a table with this site's prefix. URL rewriting no longer calls unserialize() at all, so a
 * crafted value cannot instantiate a PHP object during import.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Database
{
    /** Dump every base table for the current site's prefix into $sql_path. Returns table count. */
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

            // Stream rows in batches so a big table never loads entirely into memory. Ordered by
            // the primary key: OFFSET paging without ORDER BY may skip or repeat rows.
            $order = self::order_by($table);
            $offset = 0;
            $batch = 500;
            do {
                $rows = $wpdb->get_results(
                    $wpdb->prepare('SELECT * FROM `' . $table . '`' . $order . ' LIMIT %d OFFSET %d', $batch, $offset),
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

    /**
     * Base tables that belong to this site (current prefix, incl. multisite blog tables).
     * Views are left out: SHOW CREATE TABLE on a view yields a CREATE VIEW, which import refuses.
     */
    private static function site_tables()
    {
        global $wpdb;
        $like = $wpdb->esc_like($wpdb->prefix) . '%';
        $rows = $wpdb->get_col($wpdb->prepare(
            "SELECT TABLE_NAME FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' AND TABLE_NAME LIKE %s
             ORDER BY TABLE_NAME",
            $like
        ));
        return $rows ? $rows : array();
    }

    /** " ORDER BY <primary key columns>", or "" for a table without one. */
    private static function order_by($table)
    {
        global $wpdb;
        $keys = $wpdb->get_results('SHOW KEYS FROM `' . $table . "` WHERE Key_name = 'PRIMARY'", ARRAY_A);
        if (!$keys) {
            return '';
        }
        usort($keys, function ($a, $b) { return (int) $a['Seq_in_index'] - (int) $b['Seq_in_index']; });
        $cols = array();
        foreach ($keys as $k) {
            $cols[] = '`' . str_replace('`', '', $k['Column_name']) . '`';
        }
        return ' ORDER BY ' . implode(',', $cols);
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
     * Yields each statement of a dump, after prefix rewriting and (for dumps made by PAIO 0.1.1
     * or earlier) restoring the leaked "%" placeholder token. Shared by validate() and import()
     * so both see exactly the same statements.
     */
    private static function statements($sql_path, array $source)
    {
        global $wpdb;
        $src_prefix = isset($source['prefix']) ? (string) $source['prefix'] : $wpdb->prefix;
        $dst_prefix = $wpdb->prefix;

        // Only dumps from before the 0.1.2 fix carry the token. Applying the repair to newer dumps
        // replaced the first {64-hex} string found anywhere in real data, and then all copies of it.
        $gen = isset($source['generator']) ? (string) $source['generator'] : '';
        $legacy_token = preg_match('/^PAIO (\d+\.\d+\.\d+)/', $gen, $gm) && version_compare($gm[1], '0.1.2', '<');

        $fh = fopen($sql_path, 'rb');
        if (!$fh) {
            throw new RuntimeException('Cannot read DB dump.');
        }
        $buffer = '';
        $no = 0;
        $token = null;
        try {
            while (!feof($fh)) {
                $line = fgets($fh);
                if ($line === false) {
                    break;
                }
                $trim = ltrim($line);
                if ($buffer === '' && ($trim === '' || substr($trim, 0, 2) === '--')) {
                    continue;
                }
                $buffer .= $line;
                // A statement ends at a line finishing with ";". Our dumps put every INSERT on one
                // line (newlines inside data are escaped as \n), and CREATE TABLE ends with ";".
                if (preg_match('/;\s*$/', rtrim($line))) {
                    $stmt = trim($buffer);
                    $buffer = '';
                    if ($stmt === '') {
                        continue;
                    }
                    if ($src_prefix !== $dst_prefix) {
                        $stmt = self::rewrite_prefix($stmt, $src_prefix, $dst_prefix);
                    }
                    if ($legacy_token) {
                        if ($token === null && preg_match('/\{[0-9a-f]{64}\}/', $stmt, $m)) {
                            $token = $m[0];
                        }
                        if ($token !== null) {
                            $stmt = str_replace($token, '%', $stmt);
                        }
                    }
                    $no++;
                    yield $no => $stmt;
                }
            }
            if (trim($buffer) !== '') {
                throw new RuntimeException('Database dump ends in the middle of a statement.');
            }
        } finally {
            fclose($fh);
        }
    }

    /**
     * Checks one statement against the shapes PAIO's exporter writes. Returns null if allowed,
     * else the reason. Every table must carry this site's prefix, so a dump cannot reach other
     * installs that share the database.
     */
    public static function statement_problem($stmt, $prefix)
    {
        if (preg_match("/^SET SESSION sql_mode='[A-Z_,]*';$/", $stmt)
            || preg_match('/^SET NAMES [a-z0-9_]+( COLLATE [a-z0-9_]+)?;$/', $stmt)
            || preg_match('/^SET FOREIGN_KEY_CHECKS=[01];$/', $stmt)) {
            return null;
        }
        $table_ok = function ($t) use ($prefix) {
            return strpos($t, $prefix) === 0 && preg_match('/^[A-Za-z0-9_$]+$/', $t);
        };
        if (preg_match('/^DROP TABLE IF EXISTS `([^`]+)`;$/', $stmt, $m)) {
            return $table_ok($m[1]) ? null : 'table ' . $m[1] . ' does not use this site\'s prefix ' . $prefix;
        }
        if (preg_match('/^INSERT INTO `([^`]+)` \((`[^`]+`)(,`[^`]+`)*\) VALUES \(/', $stmt, $m)) {
            if (!$table_ok($m[1])) {
                return 'table ' . $m[1] . ' does not use this site\'s prefix ' . $prefix;
            }
            return substr($stmt, -2) === ');' ? null : 'INSERT does not end with ");"';
        }
        if (preg_match('/^CREATE TABLE `([^`]+)` \(/', $stmt, $m)) {
            if (!$table_ok($m[1])) {
                return 'table ' . $m[1] . ' does not use this site\'s prefix ' . $prefix;
            }
            $close = self::matching_paren($stmt, strlen($m[0]) - 1);
            if ($close === null) {
                return 'unbalanced CREATE TABLE';
            }
            // Table options only: no "AS SELECT", no DATA/INDEX DIRECTORY, no CONNECTION.
            $tail = preg_replace("/'(?:[^'\\\\]|\\\\.|'')*'/s", "''", substr($stmt, $close + 1));
            if (!preg_match("/^[\\sA-Za-z0-9_=',]*;$/", $tail)
                || preg_match('/\b(SELECT|DIRECTORY|CONNECTION|UNION|INSERT_METHOD)\b/i', $tail)) {
                return 'CREATE TABLE has options PAIO never writes: ' . substr(trim($tail), 0, 80);
            }
            return null;
        }
        return 'not a statement PAIO writes';
    }

    /** Index of the ")" matching the "(" at $open, skipping quoted strings and identifiers. */
    private static function matching_paren($s, $open)
    {
        $depth = 0;
        $n = strlen($s);
        for ($i = $open; $i < $n; $i++) {
            $c = $s[$i];
            if ($c === "'" || $c === '"' || $c === '`') {
                for ($i++; $i < $n; $i++) {
                    if ($s[$i] === '\\' && $c !== '`') {
                        $i++;
                    } elseif ($s[$i] === $c) {
                        if ($i + 1 < $n && $s[$i + 1] === $c) {
                            $i++;          // doubled quote
                        } else {
                            break;
                        }
                    }
                }
            } elseif ($c === '(') {
                $depth++;
            } elseif ($c === ')') {
                $depth--;
                if ($depth === 0) {
                    return $i;
                }
            }
        }
        return null;
    }

    /** Throws on the first statement PAIO would refuse. Runs nothing. */
    public static function validate($sql_path, array $source)
    {
        global $wpdb;
        foreach (self::statements($sql_path, $source) as $no => $stmt) {
            $problem = self::statement_problem($stmt, $wpdb->prefix);
            if ($problem !== null) {
                throw new RuntimeException(sprintf(
                    'Database dump refused, nothing was imported. Statement %d: %s (%s)',
                    $no, $problem, substr($stmt, 0, 120)
                ));
            }
        }
    }

    /**
     * Import a .sql dump, rewriting the source prefix to this site's prefix and the source
     * site URL to this site's URL (serialization-safe). $source is the manifest array.
     * Validated first, then executed one statement at a time via $wpdb::query.
     * Returns ['queries'=>N, 'errors'=>[first 20 database errors]].
     */
    public static function import($sql_path, array $source)
    {
        global $wpdb;

        self::validate($sql_path, $source);

        $dst_url  = untrailingslashit(site_url());
        $dst_home = untrailingslashit(home_url());
        $src_url  = isset($source['siteurl']) ? untrailingslashit($source['siteurl']) : '';
        $src_home = isset($source['home']) ? untrailingslashit($source['home']) : '';

        $count = 0;
        $errors = array();
        $suppress = $wpdb->suppress_errors(true);
        foreach (self::statements($sql_path, $source) as $no => $stmt) {
            if ($wpdb->query($stmt) === false && count($errors) < 20) {
                $errors[] = 'statement ' . $no . ': ' . $wpdb->last_error;
            }
            $count++;
        }
        $wpdb->suppress_errors($suppress);

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

        return array('queries' => $count, 'errors' => $errors);
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
     * Walks each row and rewrites serialized string lengths where the text changes.
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
            $order = self::order_by($table);
            $offset = 0;
            $batch = 500;
            do {
                $rows = $wpdb->get_results(
                    $wpdb->prepare('SELECT * FROM `' . $table . '`' . $order . ' LIMIT %d OFFSET %d', $batch, $offset),
                    ARRAY_A
                );
                if ($rows) {
                    foreach ($rows as $row) {
                        $update = array();
                        foreach ($text_cols as $col) {
                            if (!isset($row[$col]) || strpos($row[$col], $search) === false) {
                                continue;
                            }
                            $new = self::replace_value($search, $replace, $row[$col]);
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

    /**
     * Replaces $search in a stored value. Serialized data is rewritten token by token with string
     * lengths recomputed, without unserialize(): the dump is untrusted, and unserializing it would
     * instantiate whatever classes it names (PHP object injection). Strings that are themselves
     * serialized are handled recursively. Malformed serialized data falls back to a plain replace.
     */
    public static function replace_value($search, $replace, $data)
    {
        if (!is_string($data)) {
            return $data;
        }
        if (function_exists('is_serialized') ? is_serialized($data) : preg_match('/^[aOsibdNCE][:;]/', $data)) {
            $pos = 0;
            $out = self::ser_value($data, $pos, $search, $replace, 0);
            if ($out !== null && $pos === strlen($data)) {
                return $out;
            }
        }
        return str_replace($search, $replace, $data);
    }

    /** Parses one serialized value at $p, returning it with replacements applied, or null if malformed. */
    private static function ser_value($s, &$p, $search, $replace, $depth)
    {
        $n = strlen($s);
        if ($depth > 256 || $p >= $n) {
            return null;
        }
        $t = $s[$p];
        if ($t === 'N') {
            if (substr($s, $p, 2) !== 'N;') {
                return null;
            }
            $p += 2;
            return 'N;';
        }
        if ($t === 'b' || $t === 'i' || $t === 'd' || $t === 'r' || $t === 'R') {
            if (!preg_match('/\G[bidrR]:[^;]{1,64};/', $s, $m, 0, $p)) {
                return null;
            }
            $p += strlen($m[0]);
            return $m[0];
        }
        if ($t === 's') {
            if (!preg_match('/\Gs:(\d+):"/', $s, $m, 0, $p)) {
                return null;
            }
            $len = (int) $m[1];
            $start = $p + strlen($m[0]);
            if ($start + $len + 2 > $n || substr($s, $start + $len, 2) !== '";') {
                return null;
            }
            $str = substr($s, $start, $len);
            $p = $start + $len + 2;
            $new = self::replace_value($search, $replace, $str);
            return 's:' . strlen($new) . ':"' . $new . '";';
        }
        if ($t === 'a' || $t === 'O') {
            if ($t === 'a') {
                if (!preg_match('/\Ga:(\d+):\{/', $s, $m, 0, $p)) {
                    return null;
                }
                $head = $m[0];
                $count = (int) $m[1];
            } else {
                if (!preg_match('/\GO:(\d+):"/', $s, $m, 0, $p)) {
                    return null;
                }
                $nlen = (int) $m[1];
                $after = $p + strlen($m[0]) + $nlen;
                if (!preg_match('/\G":(\d+):\{/', $s, $m2, 0, $after)) {
                    return null;
                }
                $head = substr($s, $p, $after - $p) . $m2[0];
                $count = (int) $m2[1];
            }
            $p += strlen($head);
            $out = $head;
            for ($i = 0; $i < $count * 2; $i++) {
                $v = self::ser_value($s, $p, $search, $replace, $depth + 1);
                if ($v === null) {
                    return null;
                }
                $out .= $v;
            }
            if ($p >= $n || $s[$p] !== '}') {
                return null;
            }
            $p++;
            return $out . '}';
        }
        if ($t === 'C') {
            // Custom-serialized object: its payload format is the class's own, copy it verbatim.
            if (!preg_match('/\GC:(\d+):"/', $s, $m, 0, $p)) {
                return null;
            }
            $after = $p + strlen($m[0]) + (int) $m[1];
            if (!preg_match('/\G":(\d+):\{/', $s, $m2, 0, $after)) {
                return null;
            }
            $end = $after + strlen($m2[0]) + (int) $m2[1];
            if ($end >= $n || $s[$end] !== '}') {
                return null;
            }
            $out = substr($s, $p, $end + 1 - $p);
            $p = $end + 1;
            return $out;
        }
        if ($t === 'E') {
            if (!preg_match('/\GE:(\d+):"/', $s, $m, 0, $p)) {
                return null;
            }
            $end = $p + strlen($m[0]) + (int) $m[1];
            if (substr($s, $end, 2) !== '";') {
                return null;
            }
            $out = substr($s, $p, $end + 2 - $p);
            $p = $end + 2;
            return $out;
        }
        return null;
    }
}
