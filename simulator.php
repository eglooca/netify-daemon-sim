#!/usr/bin/php -q
<?php

set_time_limit(0);

$tm_start = gettimeofday(true);

require_once('config.php');

define('DAY_SECONDS', 86400);

class NetifySimulatorException extends Exception
{
    public function __construct($code, $message)
    {
        if (is_null($code)) $code = -1;

        parent::__construct(
            sprintf('%s: [%d] %s', __CLASS__, $code, $message), $code);
    }
}

class NetifyFlow
{
    public $digest = null;
    public $ip_nat = false;
    public $ip_version = 4;
    public $ip_protocol = 6;
    public $vlan_id = 0;
    public $other_type = 'remote';
    public $local_mac = null;
    public $other_mac = null;
    public $local_ip = null;
    public $other_ip = null;
    public $local_port = 0;
    public $other_port = 0;
    public $local_bytes = 0;
    public $other_bytes = 0;
    public $local_packets = 0;
    public $other_packets = 0;
    public $total_bytes = 0;
    public $total_packets = 0;
    public $detected_protocol = 0;
    public $detected_protocol_name = null;
    public $detected_service = 0;
    public $detected_service_name = null;
    public $detection_guessed = false;
    public $host_server_name = null;
    public $ssl = array('client' => null, 'server' => null);
    public $last_seen_at = 0;

    private $iface = null;
    private $protocols = array(5 => 'DNS', 91 => 'SSL', 188 => 'QUIC');
    private $services = array(
        0 => 'Unknown',
        1000 => 'netify.google',
        1001 => 'netify.gmail',
        1002 => 'netify.apple',
        1003 => 'netify.apple-icloud',
        1004 => 'netify.amazon',
        1005 => 'netify.cnn',
        1006 => 'netify.github',
        1007 => 'netify.youtube'
    );
    private $domains = array(
        0 => array('abc.com', 'def.com', 'ghi.com', 'jkl.com', 'mno.com', 'pqr.com', 'stu.com', 'vwx.com', 'xyz.com'),
        1000 => array(
            'google.com', 'google.ca', 'images.google.com', 'play.google.com'
        ),
        1001 => array(
            'gmail.com'
        ),
        1002 => array(
            'apple.com'
        ),
        1003 => array(
            'icloud.com'
        ),
        1004 => array(
            'amazon.ca', 'amazon.com'
        ),
        1005 => array(
            'cnn.com'
        ),
        1006 => array(
            'github.com'
        ),
        1007 => array(
            'youtube.com'
        )
    );

    public function __construct($iface)
    {
        $this->iface = $iface;

        $this->detected_protocol = array_rand($this->protocols);
        $this->detected_protocol_name = $this->protocols[$this->detected_protocol];

        $this->detected_service = array_rand($this->services);
        $this->detected_service_name = $this->services[$this->detected_service];

        switch ($this->detected_protocol_name) {
        case 'DNS':
            $this->ip_protocol = 17;
            $this->other_port = 53;
            $domain_id = array_rand($this->domains[$this->detected_service]);
            $this->host_server_name = $this->domains[$this->detected_service][$domain_id];
            break;
        case 'SSL':
        case 'QUIC':
            $this->other_port = 443;
            $domain_id = array_rand($this->domains[$this->detected_service]);
            $this->ssl[(mt_rand(1, 2) == 1) ? 'client' : 'server'] = '*.' .
                $this->domains[$this->detected_service][$domain_id];
            break;
        }

        $this->local_port = mt_rand(1024, 65535);
    }

    public function hash()
    {
        $this->digest = sha1($this->iface .
            $this->ip_version . $this->ip_protocol .  $this->vlan_id .
            $this->local_mac . $this->other_mac .
            $this->local_ip . $this->other_ip .
            $this->local_port . $this->other_port .
            $this->detection_guessed . $this->detected_protocol .
            $this->detected_service . $this->host_server_name .
            $this->ssl['client'] . $this->ssl['server']
        );
    }

    public function update()
    {
        $this->local_packets = mt_rand(1, 100);
        $this->other_packets = mt_rand(100, 1000);
        $this->total_packets += $this->local_packets + $this->other_packets;

        $this->local_bytes = $this->local_packets * mt_rand(10, 20);
        $this->other_bytes = $this->local_packets * mt_rand(10, 20);
        $this->total_bytes += $this->local_bytes + $this->other_bytes;

        $this->last_seen_at = intval(gettimeofday(true) * 1000);
    }
}

class NetifySimulator
{
    protected $ch = null;
    protected $json_version = 1.4;
    protected $client_version = 1.11;
    protected $match_digests = array(
        'content' => 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        'custom' => '23543c8819ebbf1deea14276b06efd8be08cb24d',
        'host' => 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    );
    protected $ifaces = array();
    protected $iface_config = array();
    protected $devices = array();
    protected $stats = array();
    protected $flows = array();
    protected $tm_next_day = 0;
    protected $flows_per_update = 0;
    protected $flows_remaining = MAX_FLOWS_PER_DAY;
    protected $stat_fields = array(
        'raw', 'ethernet', 'mpls', 'pppoe', 'vlan', 'fragmented',
        'discarded', 'discarded_bytes', 'largest_bytes',
        'ip', 'tcp', 'udp', 'ip_bytes', 'wire_bytes'
    );
    protected $remote_networks = array();
    protected $upload_buffer = array();
    protected $upload_buffer_size = 0;

    public function __construct()
    {
        global $tm_start;

        date_default_timezone_set('UTC');

        openlog('netify-simulator', (DEBUG) ? LOG_PERROR : 0, SYSLOG_FACILITY);

        $this->tm_next_day = $tm_start + floatval(DAY_SECONDS);
        $this->flows_per_update = intval(
            ceil(MAX_FLOWS_PER_DAY / (DAY_SECONDS / INTERVAL))
        );

        if (MAX_LAN_INTERFACES <= 0 && MAX_WAN_INTERFACES <= 0)
            throw new NetifySimulatorException(1, 'No interfaces defined');

        $id = 0;
        for ($i = 0; $i < MAX_LAN_INTERFACES; $i++, $id++)
            $this->add_interface('eth', $id, 'LAN');
        for ($i = 0; $i < MAX_WAN_INTERFACES; $i++, $id++)
            $this->add_interface('eth', $id, 'WAN');

        for ($i = 0; $i < MAX_REMOTE_NETS; $i++) {
            $this->remote_networks[] = sprintf('%d.%d.%d.%%d',
                mt_rand(20, 167), mt_rand(0, 254), mt_rand(0, 254));
        }

        $this->ch = curl_init();
        if ($this->ch === false)
            throw new NetifySimulatorException(1, 'Error initializing cURL');

        if (DEBUG) {
            //var_dump($this->flows_per_update);
            //var_dump($this->ifaces);
            //var_dump($this->iface_configs);
            //var_dump($this->stats);
            //var_dump($this->remote_networks);
        }
    }

    public function __destruct()
    {
        closelog();
    }

    protected function load_realm_uuid($path)
    {
        if (!file_exists($path)) {
            $ph = popen('uuidgen', 'r');
            if (!is_resource($ph)) {
                throw new NetifySimulatorException(1,
                    'Error generating realm UUID');
            }
            $uuid = trim(stream_get_contents($ph));
            if (pclose($ph) != 0) {
                throw new NetifySimulatorException(1,
                    'Error generating realm UUID');
            }

            $this->save_realm_uuid($path, $uuid);

            return $uuid;
        }

        $fh = fopen($path, 'r');
        if (!is_resource($fh)) {
            throw new NetifySimulatorException(1,
                'Error loading realm UUID');
        }

        $uuid = trim(stream_get_contents($fh));

        fclose($fh);

        return $uuid;
    }

    protected function save_realm_uuid($path, $uuid)
    {
        $fh = fopen($path, 'w');
        if (!is_resource($fh)) {
            throw new NetifySimulatorException(1,
                'Error loading realm UUID');
        }

        fprintf($fh, "$uuid\n");
        fclose($fh);
    }

    protected function add_interface($prefix, $id, $role)
    {
        $name = sprintf('%s%d', $prefix, $id);
        $this->ifaces[$name] = array('role' => $role);

        switch ($role) {
        case 'LAN':
            $config = array(
                'prefix' => 24,
                'network' => sprintf('192.168.%d.0', $id),
                'address' => sprintf('192.168.%d.1', $id),
                'station_mac' => sprintf('00:04:23:%02X:00:%%02X', $id),
                'station_addr' => sprintf('192.168.%d.%%d', $id)
            );
            break;
        case 'WAN':
            $config = array(
                'prefix' => 24,
                'network' => sprintf('10.0.%d.0', $id),
                'address' => sprintf('10.0.%d.1', $id),
                'iface_mac' => sprintf('00:04:23:%02X:00:01', $id),
                'gateway_mac' => sprintf('00:04:23:%02X:00:02', $id)
            );
            break;
        default:
            throw new NetifySimulatorException(1, "Invalid interface role: $role");
        }
        $this->iface_configs[$name] = $config;

        $stats = array();
        foreach ($this->stat_fields as $field) $stats[$field] = 0;
        $this->stats[$name] = $stats;
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

    protected function manage_flows()
    {
        $flow_count = 0;

        foreach ($this->flows as $iface => $flows) {
            foreach ($flows as $flow) {
                $flow_count++;
                $flow->update();
            }
        }

        if ($flow_count != 0) {
            $reap = $flow_count * (
                mt_rand(PURGE_PERC_LOW, PURGE_PERC_HIGH) / 100
            );
            $reap_per_iface = $reap / count($this->ifaces);

            foreach ($this->flows as $iface => $flows) {
                shuffle($this->flows[$iface]);
                for ($i = 0; $i < intval($reap_per_iface); $i++) {
                    switch (mt_rand(1, 2)) {
                    case 1:
                        array_shift($this->flows[$iface]);
                        break;
                    case 2:
                        array_pop($this->flows[$iface]);
                        break;
                    }
                    $flow_count--;
                }
            }

            NetifySimulator::debug(__METHOD__, sprintf('Reaped %d flows.', $reap));
        }

        if ($flow_count < $this->flows_per_update) {
            $create = $this->flows_per_update - $flow_count;
            $create_per_iface = $create / count($this->ifaces);

            $flow_count = 0;

            foreach ($this->ifaces as $iface => $config) {
                for ($i = 0; $i < $create_per_iface; $i++)
                    $this->create_flow($iface);
                $flow_count += count($this->flows[$iface]);
            }

            NetifySimulator::debug(__METHOD__,
                sprintf('Created %d flows, %d total.', $create, $flow_count));
        }

        foreach ($this->flows as $iface => $flows) {
            foreach ($this->stats[$iface] as $field => $stat)
                $this->stats[$iface][$field] = 0;
            foreach ($flows as $flow) {
                $this->stats[$iface]['raw'] += $flow->local_packets + $flow->other_packets;
                $this->stats[$iface]['ethernet'] += $flow->local_packets + $flow->other_packets;
                $largest = $this->stats[$iface]['largest_bytes'];
                if ($flow->local_bytes > $largest)
                    $largest = $flow->local_bytes;
                if ($flow->other_bytes > $largest)
                    $largest = $flow->other_bytes;
                $this->stats[$iface]['largest_bytes'] = $largest;
                $this->stats[$iface]['ip'] += $flow->local_packets + $flow->other_packets;
                if ($flow->ip_protocol == 6)
                    $this->stats[$iface]['tcp'] += $flow->local_packets + $flow->other_packets;
                else if ($flow->ip_protocol == 17)
                    $this->stats[$iface]['udp'] += $flow->local_packets + $flow->other_packets;
                $this->stats[$iface]['ip_bytes'] += $flow->local_bytes + $flow->other_bytes;
                $this->stats[$iface]['wire_bytes'] += intval(($flow->local_bytes + $flow->other_bytes) * 0.04);
            }
        }
    }

    protected function create_flow($iface)
    {
        $flow = new NetifyFlow($iface);

        if ($this->ifaces[$iface]['role'] == 'LAN') {
            $octet = mt_rand(100, 254);
            $flow->local_mac = sprintf($this->iface_configs[$iface]['station_mac'], $octet);
            $flow->local_ip = sprintf($this->iface_configs[$iface]['station_addr'], $octet);

            $id = mt_rand(MAX_LAN_INTERFACES, MAX_LAN_INTERFACES + MAX_WAN_INTERFACES - 1);
            reset($this->ifaces);
            for ($i = 0; $i < $id; $i++) next($this->ifaces);
            $wanif = key($this->ifaces);
            $flow->other_mac = $this->iface_configs[$wanif]['gateway_mac'];
        }
        else {
            $flow->local_mac = $this->iface_configs[$iface]['iface_mac'];
            $flow->local_ip = $this->iface_configs[$iface]['address'];
            $flow->other_mac = $this->iface_configs[$iface]['gateway_mac'];
            $flow->ip_nat = (mt_rand(1, 2) == 1) ? true : false;
        }

        $octet = mt_rand(1, 254);
        $id = array_rand($this->remote_networks);
        $flow->other_ip = sprintf($this->remote_networks[$id], $octet);

        $flow->hash();
        $flow->update();

        $this->flows[$iface][] = $flow;
    }

    protected function upload_queue()
    {
        $payload = array(
            'version' => $this->json_version,
            'timestamp' => time(),
            'content_match_digest' => $this->match_digests['content'],
            'custom_match_digest' => $this->match_digests['custom'],
            'host_match_digest' => $this->match_digests['host'],
            'interfaces' => $this->ifaces,
            'devices' => $this->devices,
            'stats' => $this->stats,
            'flows' => $this->flows
        );

        $json = gzencode(json_encode($payload, JSON_PRETTY_PRINT));

        while (
            $this->upload_buffer_size / 1024 > MAX_UPLOAD_BUFFER_SIZE) {
            $entry = array_shift($this->upload_buffer);
            $this->upload_buffer_size -= strlen($entry);
            NetifySimulator::debug(__METHOD__, sprintf(
                "dropping %d bytes from upload_buffer", strlen($entry)));
        }

        array_push($this->upload_buffer, $json);
        $this->upload_buffer_size += strlen($json);
        NetifySimulator::debug(__METHOD__, sprintf(
            "pushed %d bytes to upload_buffer", strlen($json)));

        while (count($this->upload_buffer)) {
            reset($this->upload_buffer);
            $json = current($this->upload_buffer);
            if ($this->upload_post($json) === false) {
                break;
            }
            $this->upload_buffer_size -= strlen($json);
            array_shift($this->upload_buffer);
        }

        NetifySimulator::debug(__METHOD__, sprintf(
            "upload_buffer size %d entries (%d bytes)",
            count($this->upload_buffer), $this->upload_buffer_size));
    }

    protected function upload_post($json)
    {
        $headers = array(
            'Content-Type: application/json',
            'Content-Encoding: gzip',
            'X-UUID: ' . UUID_CLIENT,
            'X-UUID-Serial: -',
            'X-UUID-Realm: ' . $this->load_realm_uuid(UUID_REALM_PATH),
        );

        $options = array(
            CURLOPT_POST => true,
            CURLOPT_URL => URL_UPLOAD,
            CURLOPT_USERAGENT => "NetifySimulator/{$this->client_version} (PHP)",
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_VERBOSE => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_ENCODING => 'gzip',
            CURLOPT_POSTFIELDS => $json,
        );

        curl_setopt_array($this->ch, $options);

        if (($result = curl_exec($this->ch)) === false)
            throw new NetifySimulatorException('Error uploading payload');

        $code = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);

        //NetifySimulator::debug(__METHOD__, $json);
        NetifySimulator::debug(__METHOD__, "NetifySink: $code");

        if (!($response = json_decode($result)))
            return false;

        switch ($response->version) {
        case 1.0:
            break;
        case $this->json_version:
            break;
        default:
            var_dump($response);
            throw new NetifySimulatorException(1,
                'Unsupported JSON response version'
            );
        }

        switch ($response->type) {
        case 1:
            break;
        case 2:
            NetifySimulator::logger(__METHOD__,
                "NetifySink: {$response->data->message} [{$response->data->code}]",
                LOG_ERR);
            return false;
        default:
            var_dump($response);
            throw new NetifySimulatorException(1,
                'Unsupported JSON response type'
            );
        }

        return ($code == 200);
    }

    public function run()
    {
        do {
            $tm_now = gettimeofday(true);

            if ($tm_now >= $this->tm_next_day) {
                $this->flows_remaining = MAX_FLOWS_PER_DAY;
                $this->tm_next_day = $tm_now + floatval(DAY_SECONDS);
            }

            $this->manage_flows();

            $this->upload_queue();

            $interval = floatval(INTERVAL) - (gettimeofday(true) - $tm_now);

            if ($interval >= 1.0) {
                NetifySimulator::debug(__METHOD__,
                    sprintf("Next upload in %.02f second(s)...", $interval));
                sleep(intval($interval));
            }
            else if ($interval < 0) {
                NetifySimulator::logger(__METHOD__,
                    sprintf("Upload took longer than interval time (%d seconds)", INTERVAL));
            }
        }
        while (true);
    }
}

$rc = 0;
$ns = new NetifySimulator();

try {
    NetifySimulator::logger(__LINE__,
        sprintf('>>> Netify Simulator: ...'), LOG_INFO);

    $ns->run();

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
