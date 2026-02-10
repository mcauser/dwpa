<?php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    ddie(400, 'This API accepts only POST requests');
}

if (!isset($redis_sock) || !is_readable($redis_sock) || !is_writeable($redis_sock)) {
    ddie(501, 'redis socket not set');
}

$modes = ['bmacssid' => 'm',
          'bpmk'     => 'p'];
$mode = substr($_SERVER['REQUEST_URI'], 1);
if (!array_key_exists($mode, $modes)) {
    ddie(400, 'mode not correct');
}

// Read request
$raw = file_get_contents("php://input");
$json = json_decode($raw, True, 2);
if (json_last_error() !== JSON_ERROR_NONE) ddie(400, 'Invalid JSON');
if (count($json) == 0 || count($json) > 300) ddie(400, 'Bad parameters count');

// Validate json request
$json_valid = True;

for ($i=0; $i<count($json); $i++) {
    if (strlen($json[$i]) != 4 || strspn($json[$i], '0123456789abcdef') != 4) {
        $json_valid = False;
        break;
    }
    $json[$i] = $modes[$mode] . $json[$i];
}

if (!$json_valid) {
    ddie(400, 'Invalid JSON payload');
}

//  Connect to pogocache
$r = new Redis();
try {
    $r->connect($redis_sock);
} catch (RedisException $e) {
    ddie(503, 'Try again later');
}

// Query pogocache
$res = $r->mget($json);
foreach ($res as &$v) {
    $v = str_split(bin2hex($v), 8);
}
$res = array_combine($json, $res);

// Strip mode letter
$res1 = [];
foreach ($res as $k => $v) {
    $res1[substr($k, 1)] = $v;
}

// Return results
header('Content-Type: application/json; charset=utf-8');
echo json_encode($res1);

function ddie($errcode = 400, $errmess = 'Go away'): void {
    http_response_code($errcode);
    die($errmess);
}
?>
