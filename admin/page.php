<?php
/** Admin page markup. Loaded only from PAIO_Admin::page() after a capability check. */
if (!defined('ABSPATH')) {
    exit;
}
$php_max = ini_get('max_execution_time');
?>
<div class="wrap paio-wrap">
    <h1>PAIO Migration <span style="font-size:13px;color:#777;font-weight:normal">v<?php echo esc_html(PAIO_VERSION); ?></span></h1>
    <p>In-house full-site migration (database + wp-content). Replaces the cracked All-In-One plugin. Every action here requires an administrator login and a security token.</p>

    <div class="card" style="max-width:none">
        <h2>Export this site</h2>
        <p>Site: <code><?php echo esc_html(home_url()); ?></code></p>
        <p><button class="button button-primary" id="paio-export">Create export archive</button>
           <span id="paio-export-status" class="paio-status"></span></p>
    </div>

    <div class="card" style="max-width:none">
        <h2>Import an archive</h2>
        <p>Upload a <code>.<?php echo esc_html(PAIO_ARCHIVE_EXT); ?></code> archive, then import it. <strong>Importing overwrites this site's wp-content and database.</strong></p>
        <p>
            <input type="file" id="paio-file" accept=".<?php echo esc_attr(PAIO_ARCHIVE_EXT); ?>">
            <button class="button" id="paio-upload">Upload</button>
            <span id="paio-upload-status" class="paio-status"></span>
        </p>
        <?php if ($php_max && (int) $php_max > 0) : ?>
        <p class="description">Server <code>max_execution_time</code> is <?php echo (int) $php_max; ?>s. For large sites, import from WP-CLI instead: <code>wp paio import &lt;file&gt;</code>.</p>
        <?php endif; ?>
    </div>

    <div class="card" style="max-width:none">
        <h2>Stored archives</h2>
        <table class="widefat striped" id="paio-list">
            <thead><tr><th>File</th><th>Size</th><th>Created (UTC)</th><th>Actions</th></tr></thead>
            <tbody><tr><td colspan="4">Loading…</td></tr></tbody>
        </table>
    </div>
</div>
<style>
.paio-wrap .card{margin-top:16px;padding:12px 18px}
.paio-status{margin-left:10px;font-weight:600}
.paio-status.ok{color:#1a7f37}.paio-status.err{color:#b32d2e}.paio-status.busy{color:#996800}
.paio-wrap .button.danger{color:#b32d2e;border-color:#b32d2e}
</style>
