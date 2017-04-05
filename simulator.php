#!/usr/bin/php -q
<?php

set_time_limit(0);

$tm_start = gettimeofday(true);

require_once('config.php');

class NetifySimulatorException extends Exception
{
    public function __construct($code, $message)
    {
        if (is_null($code)) $code = -1;

        parent::__construct(
            sprintf('%s: [%d] %s', __CLASS__, $code, $message), $code);
    }
}

class NetifySimulator
{
    public function __construct()
    {
        date_default_timezone_set('UTC');

        openlog('netify-simulator', (DEBUG) ? LOG_PERROR : 0, SYSLOG_FACILITY);
    }

    public function __destruct()
    {
        closelog();
    }

    public static function logger($method, $message, $priority = LOG_INFO)
    {
        syslog($priority, sprintf('%s: %s', $method, $message));
    }

    public static function debug($method, $message)
    {
        if (DEBUG)
            NetifySimulator::logger($method, $message, LOG_DEBUG);
    }
}

$rc = 0;
$ns = new NetifySimulator();

try {
    NetifySimulator::logger(__LINE__,
        sprintf('>>> Netify Simulator: ...'), LOG_INFO);

} catch (Exception $e) {
    NetifySimulator::logger($e->getLine(),
        sprintf('Exception: [%d] %s.',
            $e->getCode(), $e->getMessage()), LOG_ERR);

    $rc = $e->getCode();
}

NetifySimulator::logger(__LINE__,
    sprintf('<<< Netify Simulator: %.02f second(s)',
        gettimeofday(true) - $tm_start)
);

exit($rc);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
