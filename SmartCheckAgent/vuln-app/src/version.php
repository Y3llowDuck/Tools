<?php
// Machine-readable version endpoint — gives signature/fingerprint checks a
// stable JSON field to match on, in addition to response headers.
header('Content-Type: application/json');
echo json_encode([
    'php_version'    => PHP_VERSION,
    'php_version_id' => PHP_VERSION_ID,
    'sapi'           => PHP_SAPI,
    'cves'           => ['CVE-2026-109618', 'CVE-2026-109619'],
    'patched_in'     => ['8.5.12', '8.4.27', '8.3.36', '8.2.35'],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
