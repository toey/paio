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

    // ---- upload (chunked 0.1.3, checksummed + pre-checked 0.1.4) ----
    // The archive goes up in PAIO.chunk-byte pieces (default 8 MB) so a 1 GB+ file never hits
    // post_max_size / upload_max_filesize or a CDN body limit. Each piece is retried; a 409 tells us
    // the offset the server already has, so an interrupted upload continues where it stopped.
    function randomId() {
        var a = new Uint8Array(16), s = '';
        (window.crypto || window.msCrypto).getRandomValues(a);
        for (var i = 0; i < a.length; i++) { s += ('0' + a[i].toString(16)).slice(-2); }
        return s;
    }
    function fmtMB(n) { return (n / 1048576).toFixed(1) + ' MB'; }

    function toHex(buf) {
        var a = new Uint8Array(buf), s = '';
        for (var i = 0; i < a.length; i++) { s += ('0' + a[i].toString(16)).slice(-2); }
        return s;
    }
    function readSlice(blob) {                 // Blob -> ArrayBuffer (FileReader works in every browser)
        return new Promise(function (ok, bad) {
            var r = new FileReader();
            r.onload = function () { ok(r.result); };
            r.onerror = function () { bad(r.error); };
            r.readAsArrayBuffer(blob);
        });
    }
    var subtle = window.crypto && window.crypto.subtle;
    function sha256(blob) {
        if (!subtle) { return Promise.resolve(''); }   // http:// admin: no WebCrypto, server skips the check
        return readSlice(blob).then(function (b) { return subtle.digest('SHA-256', b); }).then(toHex);
    }

    // 0.1.4: walk the archive headers on this computer before sending anything. A file damaged
    // while it was downloaded keeps its size but its entries no longer line up; this finds that in
    // seconds instead of after a 1 GB upload. Resolves null when intact, else a description.
    function precheck(f, progress) {
        var dec = new TextDecoder('utf-8');
        function line(pos, want) {
            return readSlice(f.slice(pos, Math.min(f.size, pos + want))).then(function (b) {
                var u = new Uint8Array(b), i = u.indexOf(10);
                if (i < 0) {
                    if (pos + want >= f.size || want >= 1048576) { return null; }
                    return line(pos, want * 16);
                }
                return { text: dec.decode(u.subarray(0, i)).replace(/\r$/, ''), next: pos + i + 1 };
            });
        }
        return line(0, 64).then(function (m) {
            if (!m || m.text !== 'PAIO1') { return 'not a PAIO archive (bad magic)'; }
            var pos = m.next, prev = '(start of archive)', n = 0, lastTick = 0;
            function step() {
                return line(pos, 4096).then(function (l) {
                    if (!l) { return 'no PAIO_END marker (file is truncated)'; }
                    if (l.text === 'PAIO_END') { return n ? null : 'archive has no entries'; }
                    if (l.text === '') { pos = l.next; return step(); }
                    var h = null;
                    try { h = JSON.parse(l.text); } catch (e) {}
                    if (!h || typeof h.path !== 'string' || typeof h.size !== 'number' || h.size < 0) {
                        return 'bad header at byte ' + pos + ', right after entry ' + prev;
                    }
                    var end = l.next + h.size;
                    if (end + 1 > f.size) { return 'entry ' + h.path + ' runs past the end of the file (truncated)'; }
                    return readSlice(f.slice(end, end + 1)).then(function (b) {
                        if (new Uint8Array(b)[0] !== 10) {
                            return 'entry ' + h.path + ' (header at byte ' + pos + ') does not end where its size says';
                        }
                        prev = h.path; n++; pos = end + 1;
                        if (Date.now() - lastTick > 250) { lastTick = Date.now(); progress(pos); }
                        return step();
                    });
                });
            }
            return step();
        });
    }

    $('#paio-upload').on('click', function () {
        var f = $('#paio-file')[0].files[0], $s = $('#paio-upload-status'), $b = $(this);
        if (!f) { setStatus($s, 'Choose a .paio file first.', 'err'); return; }
        var chunk = parseInt(PAIO.chunk, 10) || 8388608, id = randomId(), offset = 0, tries = 0, bad = 0, t0;
        $b.prop('disabled', true);
        window.onbeforeunload = function () { return 'Upload in progress'; };
        function done(ok, text) {
            $b.prop('disabled', false); window.onbeforeunload = null;
            setStatus($s, text, ok ? 'ok' : 'err');
            if (ok) { loadList(); }
        }
        function next() {
            var end = Math.min(offset + chunk, f.size), last = end >= f.size, piece = f.slice(offset, end);
            var pct = Math.floor(offset * 100 / f.size), secs = (Date.now() - t0) / 1000;
            var rate = secs > 1 ? ' · ' + fmtMB(offset / secs) + '/s' : '';
            setStatus($s, 'Uploading… ' + pct + '% (' + fmtMB(offset) + ' of ' + fmtMB(f.size) + rate + ') — keep this tab open', 'busy');
            sha256(piece).then(function (sum) {
                var fd = new FormData();
                fd.append('action', 'paio_upload_chunk');
                fd.append('nonce', PAIO.nonces.upload);
                fd.append('upload_id', id);
                fd.append('name', f.name);
                fd.append('offset', offset);
                fd.append('total', f.size);
                fd.append('last', last ? '1' : '');
                fd.append('sha256', sum);
                fd.append('chunk', piece, 'chunk');
                send(fd);
            }, function () { done(false, 'Could not read the file on this computer.'); });
        }
        function send(fd) {
            $.ajax({ url: PAIO.ajax, method: 'POST', data: fd, processData: false, contentType: false, timeout: 300000 })
                .done(function (r) {
                    if (r && r.success) {
                        tries = 0;
                        if (r.data.done) {
                            done(true, 'Uploaded ' + r.data.file + ' (' + r.data.size + ')' + (bad ? ' — ' + bad + ' damaged piece(s) were resent' : '') + (subtle ? ', every piece checksum-verified' : ''));
                            return;
                        }
                        offset = r.data.received; next();
                    } else {
                        done(false, (r && r.data && r.data.message) || 'Upload failed.');
                    }
                })
                .fail(function (xhr) {
                    var d = null;
                    try { d = JSON.parse(xhr.responseText).data; } catch (e) {}
                    if (xhr.status === 409 && d && typeof d.expected === 'number') { offset = d.expected; tries = 0; next(); return; }
                    if (xhr.status === 422 && d && d.corrupt) {   // piece altered on the way: send it again
                        bad++;
                        if (++tries <= 8) {
                            setStatus($s, 'Piece at ' + fmtMB(offset) + ' arrived damaged, resending (' + tries + '/8)…', 'busy');
                            setTimeout(next, 1000 * tries); return;
                        }
                        done(false, 'The piece at ' + fmtMB(offset) + ' keeps arriving damaged. The network path (CDN/WAF) is altering uploads; try another network.');
                        return;
                    }
                    if (xhr.status === 403 || xhr.status === 400 || xhr.status === 422 || xhr.status === 507) {
                        done(false, (d && d.message) || ('Upload failed (HTTP ' + xhr.status + ').')); return;
                    }
                    if (++tries <= 5) {               // network blip / proxy timeout: retry the same piece
                        setStatus($s, 'Network error at ' + fmtMB(offset) + ', retrying (' + tries + '/5)…', 'busy');
                        setTimeout(next, 2000 * tries); return;
                    }
                    done(false, 'Upload failed at ' + fmtMB(offset) + ' (HTTP ' + xhr.status + '). Click Upload again to retry.');
                });
        }
        setStatus($s, 'Checking the archive on this computer…', 'busy');
        precheck(f, function (pos) {
            setStatus($s, 'Checking the archive on this computer… ' + Math.floor(pos * 100 / f.size) + '%', 'busy');
        }).then(function (err) {
            if (err) {
                done(false, 'This file is damaged (' + err + '). It was probably corrupted while it was downloaded. Download it again; nothing was uploaded.');
                return;
            }
            t0 = Date.now();
            next();
        }, function () {
            t0 = Date.now(); next();                  // could not read locally: let the server-side check decide
        });
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
        var dbOnly = $('#paio-db-only').is(':checked');
        post('import', { file: file, skip_files: dbOnly ? 1 : '' }, function (d) {
            var msg = 'Imported: ' + d.files + ' files, ' + d.queries + ' statements' + (d.from ? ' (from ' + d.from + ')' : '');
            var warn = !!(d.failed || d.refused || (d.db_errors && d.db_errors.length) || (d.dropins && d.dropins.length));
            if (d.failed) { msg += ' — ' + d.failed + ' file(s) skipped (unwritable)'; }
            if (d.refused) { msg += ' — ' + d.refused + ' file(s) refused for safety: ' + (d.refused_list || []).join(', '); }
            if (d.dropins && d.dropins.length) { msg += ' — drop-ins restored, check them: ' + d.dropins.join(', '); }
            if (d.db_errors && d.db_errors.length) { msg += ' — database errors: ' + d.db_errors.join(' | '); }
            setStatus($s, msg, warn ? 'busy' : 'ok');
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
