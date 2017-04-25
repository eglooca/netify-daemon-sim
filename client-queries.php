#!/usr/bin/php -q
<?php

require_once('config.php');
require_once('client-queries.inc.php');

date_default_timezone_set('UTC');

$fh = fopen(UUID_REALM_PATH, 'r');
if (!is_resource($fh)) {
    printf("Error opening realm UUID: %s\n", UUID_REALM_PATH);
    exit(1);
}

$uuid_realm = str_replace('-', '_', trim(stream_get_contents($fh)));
if (!strlen($uuid_realm)) {
    printf("Error reading realm UUID: %s\n", UUID_REALM_PATH);
    exit(1);
}

fclose($fh);

if (!file_exists(CLIENT_QUERY_REPORT_PATH)) {
    $fh = fopen(CLIENT_QUERY_REPORT_PATH, 'w');
    fprintf($fh, "\"timestamp\",\"query\",\"time\",\"rows\"\n");
}
else
    $fh = fopen('client-queries-report.csv', 'a+');

if (!is_resource($fh)) {
    printf("Error opening report: %s\n", CLIENT_QUERY_REPORT_PATH);
    exit(1);
}

$dbh = new PDO(sprintf('mysql:host=%s;dbname=%s',
    DB_HOST, "netify_{$uuid_realm}"), DB_USER, DB_PASS);

$stmt_query = array();
$stmt_query[] = $dbh->prepare(SQL_QUERY1);
$stmt_query[] = $dbh->prepare(SQL_QUERY2);
$stmt_query[] = $dbh->prepare(SQL_QUERY3);

function execute_query()
{
    global $fh;
    global $stmt_query;

    while (true) {
        $query_id = mt_rand(0, count($stmt_query) - 1);
        $stmt = $stmt_query[$query_id];

        $now = date_create();
        if ($query_id < 2)
            date_sub($now, date_interval_create_from_date_string('6 hours'));
        else
            date_sub($now, date_interval_create_from_date_string('1 day'));

        $timeval = strftime('%F %T', date_timestamp_get($now));

        $stmt->bindValue(':timeval', $timeval, PDO::PARAM_STR);

        $tm_start = gettimeofday(true);

        printf("%5d: Executing query%d...\n", posix_getpid(), $query_id + 1);

        $stmt->execute();

        $rows = 0;
        foreach ($stmt->fetchAll() as $row) $rows++;

        $tm_complete = gettimeofday(true) - $tm_start;
        $delay = mt_rand(CLIENT_QUERY_DELAY_LOW, CLIENT_QUERY_DELAY_HIGH);

        if (flock($fh, LOCK_EX)) {
            fprintf($fh, "%d,%d,%.02f,%d\n",
                intval(round($tm_start)), $query_id + 1, $tm_complete, $rows);
            flock($fh, LOCK_UN);
        }
        else {
            printf("%5d: Error acquiring file lock.\n", posix_getpid());
            exit(1);
        }

        printf("%5d: Fetched %d row(s) via query%d in %.02f second(s).  Sleeping for %ds...\n",
            posix_getpid(), $rows, $query_id + 1, $tm_complete, $delay);

        sleep($delay);
    }
}

for ($i = 0; $i < MAX_THREADS; $i++) {
    switch (($pid = pcntl_fork())) {
    case -1:
        printf("Error forking worker process.\n");
        exit(1);
    case 0:
        execute_query();
        break;
    default:
        printf("Started worker process: %d\n", $pid);
    }
}

pcntl_wait($status);

exit(0);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
