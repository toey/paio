<?php
/**
 * Streaming reader for the .paio format written by PAIO_Archive_Writer.
 *
 * Entries are yielded one at a time via a callback so large archives extract without
 * loading whole files into memory. Every destination path is validated by
 * PAIO_Security::safe_join() before a single byte is written.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Archive_Reader
{
    private $fh;
    private $path;
    /** Per-file write failures collected during extraction (non-fatal). */
    public $failed = array();

    public function open($path)
    {
        $this->path = $path;
        $this->fh = fopen($path, 'rb');
        if (!$this->fh) {
            throw new RuntimeException('Cannot open archive: ' . $path);
        }
        $magic = rtrim((string) fgets($this->fh), "\r\n");
        if ($magic !== PAIO_ARCHIVE_MAGIC) {
            fclose($this->fh);
            $this->fh = null;
            throw new RuntimeException('Not a PAIO archive (bad magic).');
        }
        return $this;
    }

    /**
     * Iterate entries. For each entry $callback is called with (array $header, callable $copy_to).
     *   - $header: ['path'=>..,'size'=>..,'mtime'=>..]
     *   - $copy_to($abs_dest): streams the entry payload into $abs_dest, or pass null to skip.
     * The callback returns the chosen destination abs path (or false to skip the payload).
     */
    public function each(callable $callback)
    {
        while (true) {
            $line = fgets($this->fh);
            if ($line === false) {
                throw new RuntimeException('Unexpected end of archive (no PAIO_END marker).');
            }
            $line = rtrim($line, "\r\n");
            if ($line === 'PAIO_END') {
                break;
            }
            if ($line === '') {
                continue;
            }
            $header = json_decode($line, true);
            if (!is_array($header) || !isset($header['path'], $header['size'])) {
                throw new RuntimeException('Corrupt archive header: ' . substr($line, 0, 120));
            }
            $size = (int) $header['size'];
            if ($size < 0) {
                throw new RuntimeException('Invalid entry size.');
            }

            $dest = call_user_func($callback, $header);
            if ($dest) {
                $this->stream_payload($dest, $size, !empty($header['mtime']) ? (int) $header['mtime'] : 0);
            } else {
                $this->skip_payload($size);
            }
            // Consume the single trailing "\n" after the payload.
            fread($this->fh, 1);
        }
        return $this;
    }

    private function stream_payload($dest, $size, $mtime)
    {
        $dir = dirname($dest);
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        $out = @fopen($dest, 'wb');
        if (!$out) {
            // Non-fatal: one unwritable target (e.g. a root-owned or locked file) should not
            // abort the whole restore. Record it, skip the payload, keep going.
            $this->failed[] = $dest;
            $this->skip_payload($size);
            return;
        }
        $remaining = $size;
        while ($remaining > 0) {
            $chunk = fread($this->fh, min(1048576, $remaining));
            if ($chunk === '' || $chunk === false) {
                fclose($out);
                throw new RuntimeException('Truncated archive while reading ' . basename($dest));
            }
            fwrite($out, $chunk);
            $remaining -= strlen($chunk);
        }
        fclose($out);
        if ($mtime) {
            @touch($dest, $mtime);
        }
    }

    private function skip_payload($size)
    {
        $remaining = $size;
        while ($remaining > 0) {
            $chunk = fread($this->fh, min(1048576, $remaining));
            if ($chunk === '' || $chunk === false) {
                throw new RuntimeException('Truncated archive.');
            }
            $remaining -= strlen($chunk);
        }
    }

    /** Read one named entry fully into a string (used for manifest + database.sql). */
    public function read_entry_to_string($wanted)
    {
        $found = null;
        $this->each(function ($header) use ($wanted, &$found) {
            if ($header['path'] === $wanted) {
                // Capture into a temp file then return its path via closure state.
                $tmp = wp_tempnam('paio-entry');
                $found = $tmp;
                return $tmp;
            }
            return false;
        });
        if ($found === null) {
            return null;
        }
        $data = file_get_contents($found);
        @unlink($found);
        return $data;
    }

    /**
     * Structure check without extracting anything (0.1.4): walks every header and seeks over the
     * payloads, so a 1 GB archive is checked in about a second. Returns null when the archive is
     * intact, else a short description of where it breaks. Catches a file damaged in transit
     * (download or upload), where the byte counts no longer line up with the headers.
     */
    public static function verify($path)
    {
        $fh = @fopen($path, 'rb');
        if (!$fh) {
            return 'cannot open the file';
        }
        $size = (int) filesize($path);
        $magic = rtrim((string) fgets($fh), "\r\n");
        if ($magic !== PAIO_ARCHIVE_MAGIC) {
            fclose($fh);
            return 'not a PAIO archive (bad magic)';
        }
        $prev = '(start of archive)';
        $n = 0;
        while (true) {
            $pos = ftell($fh);
            $line = fgets($fh);
            if ($line === false) {
                fclose($fh);
                return 'no PAIO_END marker (file is truncated)';
            }
            $line = rtrim($line, "\r\n");
            if ($line === 'PAIO_END') {
                break;
            }
            if ($line === '') {
                continue;
            }
            $h = json_decode($line, true);
            if (!is_array($h) || !isset($h['path'], $h['size']) || (int) $h['size'] < 0) {
                fclose($fh);
                return 'bad header at byte ' . $pos . ', right after entry ' . $prev;
            }
            $end = ftell($fh) + (int) $h['size'];
            if ($end + 1 > $size) {
                fclose($fh);
                return 'entry ' . $h['path'] . ' runs past the end of the file (truncated)';
            }
            fseek($fh, $end);
            if (fread($fh, 1) !== "\n") {
                fclose($fh);
                return 'entry ' . $h['path'] . ' (header at byte ' . $pos . ') does not end where its size says';
            }
            $prev = $h['path'];
            $n++;
        }
        fclose($fh);
        return $n > 0 ? null : 'archive has no entries';
    }

    public function close()
    {
        if ($this->fh) {
            fclose($this->fh);
            $this->fh = null;
        }
    }
}
