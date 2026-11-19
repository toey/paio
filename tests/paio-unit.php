<?php
// PAIO 0.1.5 pure checks, no WordPress needed:  php tests/paio-unit.php
define('ABSPATH', __DIR__ . '/');
require __DIR__ . '/../includes/class-paio-security.php';
require __DIR__ . '/../includes/class-paio-database.php';

$pass = 0; $fail = 0;
function ok($c, $m) { global $pass, $fail; if ($c) { $pass++; } else { $fail++; echo "FAIL $m\n"; } }

// --- file placement -----------------------------------------------------------------------
ok(PAIO_Security::code_zone('plugins/x/x.php') === 'code', 'plugin php allowed');
ok(PAIO_Security::code_zone('languages/x.l10n.php') === 'code', 'l10n php allowed');
ok(PAIO_Security::code_zone('db.php') === 'dropin', 'db.php is a drop-in');
ok(PAIO_Security::code_zone('index.php') === 'code', 'wp-content index.php allowed');
ok(PAIO_Security::code_zone('uploads/2026/shell.php') === false, 'php in uploads refused');
ok(PAIO_Security::code_zone('evil.php') === false, 'unknown root php refused');
ok(PAIO_Security::code_zone('well-known/acme-challenge/a/index.php') === false, 'Family J path refused');
ok(PAIO_Security::is_exec('uploads/x.PhTmL') && PAIO_Security::is_exec('uploads/cfs.inc') && PAIO_Security::is_exec('x/bash.fbi'), 'exec extensions');
ok(!PAIO_Security::is_exec('uploads/a.jpg') && !PAIO_Security::is_exec('uploads/php.txt'), 'non-exec');

// --- .htaccess ------------------------------------------------------------------------------
$good = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule ^index\\.php$ - [L]\n</IfModule>\n"
      . "<FilesMatch \"\\.(php|phtml)$\">\n  Require all denied\n  SetHandler none\n  ForceType text/plain\n</FilesMatch>\n"
      . "Options -Indexes -ExecCGI\nAddType font/woff2 .woff2\n";
ok(PAIO_Security::htaccess_problem($good) === null, 'protective .htaccess passes');
foreach (array(
    "AddHandler application/x-httpd-php .jpg",
    "AddType application/x-httpd-php .png",
    "SetHandler application/x-httpd-php",
    "  php_value auto_prepend_file /tmp/x",
    "php_flag engine on",
    "Options +ExecCGI\nAddHandler cgi-script .fbi",
    "Options Includes",
    "<FilesMatch x>\nSetHandler proxy:unix:/run/php-fpm.sock|fcgi://localhost\n</FilesMatch>",
) as $bad) {
    ok(PAIO_Security::htaccess_problem($bad) !== null, 'hostile .htaccess refused: ' . strtok($bad, "\n"));
}

// --- SQL statement shapes ---------------------------------------------------------------------
$p = 'wp_';
foreach (array(
    "SET SESSION sql_mode='';",
    "SET NAMES utf8mb4;",
    "SET FOREIGN_KEY_CHECKS=0;",
    "DROP TABLE IF EXISTS `wp_options`;",
    "CREATE TABLE `wp_x` (\n  `id` bigint(20) NOT NULL AUTO_INCREMENT,\n  `v` longtext DEFAULT 'a;b)',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci COMMENT='it''s (fine) SELECT';",
    "INSERT INTO `wp_options` (`option_id`,`option_value`) VALUES (1,'x); DROP TABLE wp_users; --');",
) as $s) {
    ok(PAIO_Database::statement_problem($s, $p) === null, 'allowed: ' . substr($s, 0, 40));
}
foreach (array(
    "DROP TABLE IF EXISTS `other_users`;",
    "DROP DATABASE wp;",
    "INSERT INTO `wp2_users` (`ID`) VALUES (1);",
    "UPDATE `wp_users` SET user_pass='x';",
    "GRANT ALL ON *.* TO 'x'@'%';",
    "CREATE TABLE `wp_x` (a int) AS SELECT * FROM mysql.user;",
    "CREATE TABLE `wp_x` (a int) SELECT x FROM y WHERE z IN (1);",
    "CREATE TABLE `wp_x` (a int) ENGINE=InnoDB DATA DIRECTORY='/tmp';",
    "CREATE VIEW `wp_v` AS SELECT 1;",
    "CREATE TABLE `wp_x` (a int) ENGINE=CONNECT CONNECTION='mysql://x';",
    "SET GLOBAL general_log=1;",
    "SELECT LOAD_FILE('/etc/passwd') INTO OUTFILE '/tmp/x';",
) as $s) {
    ok(PAIO_Database::statement_problem($s, $p) !== null, 'refused: ' . substr($s, 0, 50));
}

// --- serialized replace without unserialize -------------------------------------------------------
class PaioProbe { public static $hits = 0; public $u = ''; public function __wakeup() { self::$hits++; } public function __destruct() { self::$hits++; } }
$from = 'http://old.test'; $to = 'https://new.example.go.th';
$arr = array('home' => $from . '/x', 'n' => 5, 'f' => 1.5, 'b' => true, 'nul' => null, 'nested' => serialize(array($from)));
$out = PAIO_Database::replace_value($from, $to, serialize($arr));
$back = unserialize($out);
ok($back['home'] === $to . '/x' && $back['n'] === 5 && $back['b'] === true && $back['nul'] === null, 'array replaced with lengths fixed');
ok(unserialize($back['nested']) === array($to), 'nested serialized string replaced');

$obj = 'O:9:"PaioProbe":1:{s:1:"u";s:' . strlen($from) . ':"' . $from . '";}';
$before = PaioProbe::$hits;
$r = PAIO_Database::replace_value($from, $to, $obj);
ok(PaioProbe::$hits === $before, 'no object instantiated during replace');
ok($r === 'O:9:"PaioProbe":1:{s:1:"u";s:' . strlen($to) . ':"' . $to . '";}', 'object property replaced, class kept');
ok(PAIO_Database::replace_value($from, $to, 'plain ' . $from) === 'plain ' . $to, 'plain text replaced');
ok(PAIO_Database::replace_value($from, $to, 's:99:"' . $from . '";') === 's:99:"' . $to . '";', 'malformed serialized falls back to plain replace');
$utf = serialize(array('t' => 'สวัสดี ' . $from));
ok(unserialize(PAIO_Database::replace_value($from, $to, $utf)) === array('t' => 'สวัสดี ' . $to), 'multibyte lengths are bytes');

echo "paio-unit: $pass passed, $fail failed\n";
exit($fail ? 1 : 0);
