<?php
header('Content-Type: text/html; charset=utf-8');

function sanitizeTarget($t) {
    return preg_replace('/[^a-zA-Z0-9\.\-_:\/]/', '', $t);
}

$target = isset($_GET['target']) ? sanitizeTarget($_GET['target']) : '';
if (!$target) { die("Invalid target."); }

echo "<h2>Scanning results for: <em>{$target}</em></h2>";
echo "<pre>";

// ---------- 1. Basic HTTP request ----------
$ch = curl_init($target);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_HEADER => true,
    CURLOPT_NOBODY => false
]);
$response = curl_exec($ch);
$info = curl_getinfo($ch);
curl_close($ch);

echo "HTTP STATUS: {$info['http_code']}\n";
echo "Content-Type: {$info['content_type']}\n";
echo "Total Time: {$info['total_time']}s\n\n";

// ---------- 2. Security headers ----------
$headers = [];
foreach (explode("\n", $response) as $line) {
    if (strpos($line, ':') !== false) {
        list($k, $v) = explode(':', $line, 2);
        $headers[trim($k)] = trim($v);
    }
}
$expected = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Strict-Transport-Security',
    'Referrer-Policy'
];
echo "=== Security Headers Check ===\n";
foreach ($expected as $h) {
    if (isset($headers[$h])) {
        echo "[OK]   {$h}: {$headers[$h]}\n";
    } else {
        echo "[MISS] {$h}\n";
    }
}
echo "\n";

// ---------- 3. Open Port test (80/443) ----------
$ports = [80,443];
foreach ($ports as $p) {
    $conn = @fsockopen(parse_url($target, PHP_URL_HOST) ?: $target, $p, $errno, $errstr, 2);
    if ($conn) {
        echo "[OPEN] Port $p reachable\n";
        fclose($conn);
    } else {
        echo "[CLOSE] Port $p not reachable ($errstr)\n";
    }
}
echo "\n";

// ---------- 4. SSL certificate info ----------
$host = parse_url($target, PHP_URL_HOST) ?: $target;
$ctx = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
$client = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
if ($client) {
    $params = stream_context_get_params($client);
    $cert = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);
    echo "=== SSL Certificate ===\n";
    echo "Issuer: " . $cert['issuer']['O'] . "\n";
    echo "Valid From: " . date('Y-m-d', $cert['validFrom_time_t']) . "\n";
    echo "Valid To:   " . date('Y-m-d', $cert['validTo_time_t']) . "\n";
    echo "Subject CN: " . $cert['subject']['CN'] . "\n";
    fclose($client);
} else {
    echo "Could not fetch SSL certificate info.\n";
}
echo "</pre>";
?>

