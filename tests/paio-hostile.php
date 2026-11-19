<?php
// PAIO 0.1.5 end-to-end: a hostile archive is refused or filtered. Run on a TEST site only:
//   wp eval-file wp-content/plugins/paio/tests/paio-hostile.php
// Creates and removes its own files (wp-content/{plugins,uploads}/paio-hostile-test/) and table.
global $wpdb;
$pass = 0; $fail = 0;
$ok = function ($c, $m) use (&$pass, &$fail) { if ($c) { $pass++; } else { $fail++; echo "FAIL $m\n"; } };

$pfx = $wpdb->prefix;
$tbl = $pfx . 'paio_hostile_t';
$plug = WP_CONTENT_DIR . '/plugins/paio-hostile-test';
$upl  = WP_CONTENT_DIR . '/uploads/paio-hostile-test';
$manifest = wp_json_encode(array('generator' => 'PAIO 0.1.5', 'prefix' => $pfx,
    'siteurl' => site_url(), 'home' => home_url()));

$build = function ($sql, array $files) use ($manifest) {
    $sqlf = wp_tempnam('paio-h-sql');
    file_put_contents($sqlf, $sql);
    $path = wp_tempnam('paio-h') . '.paio';
    $w = new PAIO_Archive_Writer();
    $w->open($path);
    $w->add_string('package.json', $manifest);
    $w->add_file($sqlf, 'database.sql');
    foreach ($files as $rel => $body) {
        $w->add_string('wp-content/' . $rel, $body);
    }
    $w->close();
    @unlink($sqlf);
    return $path;
};
$rmrf = function ($d) {
    if (!is_dir($d)) { return; }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) { $f->isDir() && !$f->isLink() ? rmdir($f->getPathname()) : unlink($f->getPathname()); }
    rmdir($d);
};

// 1. A dump touching a table without this site's prefix is refused before ANY file is written.
$a = $build("SET NAMES utf8mb4;\nDROP TABLE IF EXISTS `zz_other_site_users`;\n",
    array('plugins/paio-hostile-test/probe.txt' => 'x'));
$msg = '';
try { PAIO_Importer::run($a, array('via' => 'cli')); } catch (Exception $e) { $msg = $e->getMessage(); }
$ok(strpos($msg, 'refused') !== false, 'foreign-prefix dump refused: ' . $msg);
$ok(!file_exists($plug . '/probe.txt'), 'no file written when the dump is refused');
@unlink($a);

// 2. Valid dump + mixed files: code goes where code belongs, the rest is filtered.
$sql = "SET NAMES utf8mb4;\nDROP TABLE IF EXISTS `$tbl`;\n"
     . "CREATE TABLE `$tbl` (\n  `id` int NOT NULL,\n  `v` longtext,\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
     . "INSERT INTO `$tbl` (`id`,`v`) VALUES (1,'" . esc_sql(serialize(array('u' => site_url() . '/x'))) . "');\n";
$b = $build($sql, array(
    'plugins/paio-hostile-test/ok.php'       => "<?php // paio test probe, inert\n",
    'plugins/paio-hostile-test/.htaccess'    => "Require all denied\n",
    'uploads/paio-hostile-test/a.txt'        => 'data',
    'uploads/paio-hostile-test/shell.php'    => "<?php /* paio test: must be refused */\n",
    'uploads/paio-hostile-test/x.phtml'      => "<?php /* refused */\n",
    'uploads/paio-hostile-test/.user.ini'    => "auto_prepend_file=/tmp/x\n",
    'uploads/paio-hostile-test/.htaccess'    => "AddHandler application/x-httpd-php .jpg\n",
));
$res = PAIO_Importer::run($b, array('via' => 'cli'));
$refused = array_map(function ($r) { return $r[0]; }, $res['refused']);
$ok(is_file($plug . '/ok.php') && is_file($plug . '/.htaccess'), 'plugin php + protective .htaccess restored');
$ok(is_file($upl . '/a.txt'), 'plain upload restored');
$ok(!file_exists($upl . '/shell.php') && !file_exists($upl . '/x.phtml'), 'php in uploads refused');
$ok(!file_exists($upl . '/.user.ini') && !file_exists($upl . '/.htaccess'), '.user.ini and handler .htaccess refused');
$ok(count($refused) === 4, 'four refusals reported (' . count($refused) . ')');
$ok($wpdb->get_var("SELECT COUNT(*) FROM `$tbl`") === '1' && empty($res['db_errors']), 'valid dump imported without errors');
@unlink($b);

// 3. GUI path honours DISALLOW_FILE_MODS (only checkable where the constant is set).
if (defined('DISALLOW_FILE_MODS') && DISALLOW_FILE_MODS) {
    $c = $build("SET NAMES utf8mb4;\n", array('uploads/paio-hostile-test/b.txt' => 'x'));
    $msg = '';
    try { PAIO_Importer::run($c, array('via' => 'gui')); } catch (Exception $e) { $msg = $e->getMessage(); }
    $ok(strpos($msg, 'DISALLOW_FILE_MODS') !== false && !file_exists($upl . '/b.txt'), 'GUI file import blocked by DISALLOW_FILE_MODS');
    @unlink($c);
} else {
    echo "note: DISALLOW_FILE_MODS not set here, GUI gate not exercised\n";
}

// Clean up.
$wpdb->query("DROP TABLE IF EXISTS `$tbl`");
$rmrf($plug);
$rmrf($upl);
echo "paio-hostile: $pass passed, $fail failed\n";
