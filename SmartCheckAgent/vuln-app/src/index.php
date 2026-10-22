<?php
// Deliberately-vulnerable test target for CVE-2026-109618 / CVE-2026-109619.
// The PHP runtime version is what matters here, not this application code.
header('X-App-Name: smartcheck-vuln-target');
$php = PHP_VERSION;
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SmartCheck Vuln Target</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 3rem auto; line-height: 1.5; }
    code { background: #f0f0f0; padding: .1rem .3rem; border-radius: 3px; }
    .warn { color: #a00; }
  </style>
</head>
<body>
  <h1>SmartCheck — PHP detection test target</h1>
  <p class="warn"><strong>For local security-detection testing only.</strong></p>
  <p>This host runs <code>PHP <?= htmlspecialchars($php) ?></code>, which is
     before the patched releases for CVE-2026-109618 and CVE-2026-109619
     (php2shell). Version-based detection should flag it.</p>
  <ul>
    <li><a href="/version.php">/version.php</a> — machine-readable version JSON</li>
    <li><a href="/info.php">/info.php</a> — full <code>phpinfo()</code></li>
  </ul>
</body>
</html>
