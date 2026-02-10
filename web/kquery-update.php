<?php
// wpa-sec K-anonymity interface DB cache export

// run this only via cli
if(php_sapi_name() !== 'cli') {
    die('Run this from cli');
}

require('conf.php');

if (!isset($redis_sock) || !is_readable($redis_sock) || !is_writeable($redis_sock)) {
    die('redis conf not set');
}

require('db.php');
require('common.php');

$r = new Redis();
try {
    $r->connect($redis_sock);
    if (! $r->ping()) {
        throw new Exception('Ping unsuccessful');
    }
} catch (RedisException $e) {
    $msg = $e->getMessage();
    die("Can't connect to redis socket $redis_sock Error: $e\n");
}

$sql = [
    'p' => "SELECT CONCAT('p', LEFT(h, 4)) AS cl, RIGHT(h, 8) AS end FROM (SELECT DISTINCT SHA1(LOWER(HEX(pmk))) AS h FROM nets WHERE n_state = 1) AS x ORDER BY 1",
    'm' => "SELECT CONCAT('m', LEFT(h, 4)) AS cl, RIGHT(h, 8) AS end FROM (SELECT DISTINCT SHA1(LOWER(CONCAT(LPAD(HEX(bssid), 12, '0'), HEX(ssid)))) AS h FROM nets WHERE n_state = 1) AS x ORDER BY 1"
       ];

foreach($sql as $m => $s) {
    $stmt = $mysql->stmt_init();
    $stmt->prepare($s);
    $stmt->execute();
    $stmt->bind_result($clid, $end);

    $tfn = tempnam($data_dir, $m);
    $fd = gzopen($tfn, 'wb9');
    gzwrite($fd, '{');

    $clid_curr = $m . '0000';
    $ends = '';
    while ($stmt->fetch()) {
        if ($clid == $clid_curr) {
            $ends .= $end;
        } else {
            $r->set($clid_curr, hex2bin($ends));

            $e = [];
            $e[substr($clid_curr, 1)] = str_split($ends, 8);
            gzwrite($fd, substr(json_encode($e), 1, -1) . ',');

            $clid_curr = $clid;
            $ends = '';
        }
    }
    if (strlen($ends) > 0) {
        $r->set($clid, hex2bin($ends));
        $e = [];
        $e[substr($clid_curr, 1)] = str_split($ends, 8);
        gzwrite($fd, substr(json_encode($e), 1, -1) . '}');
    } else {
        gzseek($fd, -1);
        gzwrite($fd, '}');
    }

    $r->save();
    $r->rawcommand('PURGE', 'ASYNC');
    $r->close();

    gzclose($fd);
    if ($m == 'p') {
        rename($tfn, $data_dir . '/wpasec_pmk.json.gz');
    } elseif ($m == 'm') {
        rename($tfn, $data_dir . '/wpasec_macssid.json.gz');
    }
}
