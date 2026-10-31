<?php
// PAIO: a "%" survives export (no placeholder token in the dump) and a 0.1.1 dump's token is restored on import.
global $wpdb;
$pass = 0; $fail = 0;
$ok = function ($c, $m, $x = '') use (&$pass, &$fail) { if ($c) { $pass++; } else { $fail++; echo "FAIL $m " . substr($x, 0, 300) . "\n"; } };
$val = 'width="100%" /archives/%post_id% ' . serialize(array('u' => 'a%3Ab'));
$m = new ReflectionMethod('PAIO_Database', 'insert_sql'); $m->setAccessible(true);
$sql = $m->invoke(null, 'wp_x', array('v' => $val));
$ok(strpos($sql, '100%') !== false && !preg_match('/\{[0-9a-f]{64}\}/', $sql), 'export keeps %', $sql);

$t = $wpdb->prefix . 'paio_pct_test';
$wpdb->query("DROP TABLE IF EXISTS `$t`");
$tok = '{' . str_repeat('ab', 32) . '}';
$f = tempnam(sys_get_temp_dir(), 'paio');
file_put_contents($f, "CREATE TABLE `$t` (id int primary key, v longtext);\n"
    . "INSERT INTO `$t` (`id`,`v`) VALUES (1,'" . esc_sql(str_replace('%', 'TOKEN', $val)) . "');\n");
file_put_contents($f, str_replace('TOKEN', $tok, file_get_contents($f)));
PAIO_Database::import($f, array('prefix' => $wpdb->prefix, 'siteurl' => site_url(), 'home' => home_url()));
$got = $wpdb->get_var("SELECT v FROM `$t` WHERE id=1");
$ok($got === $val, 'import restores a 0.1.1 token to %', $got);
$wpdb->query("DROP TABLE IF EXISTS `$t`");
unlink($f);
echo "paio-pct: $pass passed, $fail failed\n";
