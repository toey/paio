<?php
/**
 * Streaming archive writer for the .paio format.
 *
 * Format (line-oriented header + raw payload, streamable, never loads a whole file
 * into memory):
 *
 *     PAIO1\n                             <- magic, exactly once at the top
 *     {"path":"...","size":N,"mtime":N}\n <- one JSON header line per entry
 *     <N raw bytes><\n>                   <- the entry payload, then a single \n
 *     ... repeated ...
 *     PAIO_END\n                          <- end marker
 *
 * The JSON header keeps paths intact (UTF-8, spaces, Thai) without fixed-width fields.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PAIO_Archive_Writer
{
    private $fh;
    private $path;
    private $count = 0;

    public function open($path)
    {
        $this->path = $path;
        $this->fh = fopen($path, 'wb');
        if (!$this->fh) {
            throw new RuntimeException('Cannot open archive for writing: ' . $path);
        }
        fwrite($this->fh, PAIO_ARCHIVE_MAGIC . "\n");
        return $this;
    }

    /** Add a file from disk, stored under the relative path $rel. */
    public function add_file($abs, $rel)
    {
        $size = filesize($abs);
        if ($size === false) {
            throw new RuntimeException('Cannot stat file: ' . $abs);
        }
        $in = fopen($abs, 'rb');
        if (!$in) {
            throw new RuntimeException('Cannot read file: ' . $abs);
        }
        $this->write_header($rel, $size, @filemtime($abs));
        stream_copy_to_stream($in, $this->fh);
        fclose($in);
        fwrite($this->fh, "\n");
        $this->count++;
        return $this;
    }

    /** Add an in-memory string (used for the manifest and the DB dump when small). */
    public function add_string($rel, $content)
    {
        $this->write_header($rel, strlen($content), time());
        fwrite($this->fh, $content);
        fwrite($this->fh, "\n");
        $this->count++;
        return $this;
    }

    private function write_header($rel, $size, $mtime)
    {
        $header = wp_json_encode(array(
            'path'  => (string) $rel,
            'size'  => (int) $size,
            'mtime' => (int) ($mtime ?: time()),
        ));
        fwrite($this->fh, $header . "\n");
    }

    public function close()
    {
        if ($this->fh) {
            fwrite($this->fh, "PAIO_END\n");
            fclose($this->fh);
            $this->fh = null;
        }
        return $this->count;
    }
}
