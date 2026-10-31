/* PAIO admin UI. Sends the per-action nonce with every request. No unauthenticated paths. */
(function ($) {
    'use strict';

    function post(action, data, done, fail) {
        data = data || {};
        data.action = 'paio_' + action;
        data.nonce = PAIO.nonces[action];
        $.post(PAIO.ajax, data)
            .done(function (r) {
                if (r && r.success) { done(r.data); }
                else { (fail || noop)((r && r.data && r.data.message) || 'Request failed.'); }
            })
            .fail(function (xhr) {
                var m = 'Server error';
                try { m = JSON.parse(xhr.responseText).data.message; } catch (e) {}
                (fail || noop)(m);
            });
    }
    function noop() {}
    function setStatus($el, text, cls) { $el.attr('class', 'paio-status ' + (cls || '')).text(text); }

    // ---- export ----
    $('#paio-export').on('click', function () {
        var $b = $(this), $s = $('#paio-export-status');
        $b.prop('disabled', true);
        setStatus($s, 'Exporting… (do not close this tab)', 'busy');
        post('export', {}, function (d) {
            $b.prop('disabled', false);
            setStatus($s, 'Done: ' + d.file + ' (' + d.files + ' files, ' + d.tables + ' tables, ' + d.size + ')', 'ok');
            loadList();
        }, function (m) {
            $b.prop('disabled', false);
            setStatus($s, m, 'err');
        });
    });

    // ---- upload ----
    $('#paio-upload').on('click', function () {
        var f = $('#paio-file')[0].files[0], $s = $('#paio-upload-status');
        if (!f) { setStatus($s, 'Choose a .paio file first.', 'err'); return; }
        var fd = new FormData();
        fd.append('action', 'paio_upload');
        fd.append('nonce', PAIO.nonces.upload);
        fd.append('archive', f);
        setStatus($s, 'Uploading…', 'busy');
        $.ajax({ url: PAIO.ajax, method: 'POST', data: fd, processData: false, contentType: false })
            .done(function (r) {
                if (r && r.success) { setStatus($s, 'Uploaded ' + r.data.file + ' (' + r.data.size + ')', 'ok'); loadList(); }
                else { setStatus($s, (r && r.data && r.data.message) || 'Upload failed.', 'err'); }
            })
            .fail(function () { setStatus($s, 'Upload failed.', 'err'); });
    });

    // ---- list / import / download / delete ----
    function loadList() {
        post('list', {}, function (rows) {
            var $tb = $('#paio-list tbody').empty();
            if (!rows.length) { $tb.append('<tr><td colspan="4">No archives yet.</td></tr>'); return; }
            rows.forEach(function (r) {
                var $tr = $('<tr>');
                $tr.append($('<td>').append($('<code>').text(r.file)));
                $tr.append($('<td>').text(r.size));
                $tr.append($('<td>').text(r.date));
                var $act = $('<td>');
                $act.append($('<button class="button button-primary">').text('Import').on('click', function () { doImport(r.file); }));
                $act.append(' ');
                $act.append($('<a class="button">').attr('href',
                    PAIO.ajax + '?action=paio_download&nonce=' + encodeURIComponent(PAIO.nonces.download) + '&file=' + encodeURIComponent(r.file)
                ).text('Download'));
                $act.append(' ');
                $act.append($('<button class="button danger">').text('Delete').on('click', function () { doDelete(r.file); }));
                $tr.append($act);
                $tb.append($tr);
            });
        }, function () {
            $('#paio-list tbody').html('<tr><td colspan="4">Could not load list.</td></tr>');
        });
    }

    function doImport(file) {
        if (!window.confirm('Import ' + file + '?\n\nThis OVERWRITES this site\'s wp-content and database. Make an export first if unsure.')) {
            return;
        }
        var $s = $('#paio-upload-status');
        setStatus($s, 'Importing ' + file + '… (do not close this tab)', 'busy');
        post('import', { file: file }, function (d) {
            var msg = 'Imported: ' + d.files + ' files, ' + d.queries + ' statements' + (d.from ? ' (from ' + d.from + ')' : '');
            if (d.failed) { msg += ' — ' + d.failed + ' file(s) skipped (unwritable)'; }
            setStatus($s, msg, d.failed ? 'busy' : 'ok');
        }, function (m) {
            setStatus($s, m, 'err');
        });
    }

    function doDelete(file) {
        if (!window.confirm('Delete ' + file + '?')) { return; }
        post('delete', { file: file }, loadList);
    }

    $(loadList);
})(jQuery);
