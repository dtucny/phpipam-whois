#!/bin/php -q
<?php
// PHPIPAM Whois - simple whois server implementation 
//		   getting info from PHPIPAM via API 

$toolname = "PHPIPAM Whois";
$toolvers = "0.1";

///////////////////
// Config        //
///////////////////

$bindaddr = '0.0.0.0';
$bindport = 43;

// IPAM API Config
$ipam_api_url    = "https://phpipam.example.com/api/";		// IPAM server url
$ipam_api_app_id = "<YourAppID>";				// IPAM application id
$ipam_api_key    = "<YourAppKey>";				// api key - only for encrypted methods, otherwise must be false

# set username / password for authentication, not needed for encrypted communications
$ipam_api_username = "";
$ipam_api_password = "";

# save token or not ?
#   false => dont save, check each time
#   filename => will save token to filename provided
$ipam_token_file = false;

# set result format json/object/array/xml
$ipam_result_format = "array";

$debug = 9;

error_reporting(E_ALL ^ E_NOTICE ^ E_STRICT);

///////////////////
// End of Config //
///////////////////

require 'phpipam-api-clients/php-client/class.phpipam-api.php';
$ipamapi = new phpipam_api_client ($ipam_api_url, $ipam_api_app_id, $ipam_api_key, $ipam_api_username, $ipam_api_password, $ipam_result_format);

// Create Socket
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if ($sock == FALSE) {
	echo "Error: Socket could not be created\n";
	exit(1);
}

// Set socket option to re-use so that we can bind even if the socket is in timewait
if (!socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1)) { 
	echo socket_strerror(socket_last_error($sock)); 
	exit(2); 
} 

// Bind to IP:PORT
if (!socket_bind($sock, $bindaddr, $bindport)) {
	echo "Error: Bind failed to $bindaddr:$bindport\n";
	echo socket_strerror(socket_last_error($sock)); 
	exit(3);
}

// Start listening
if (!socket_listen($sock)) {
	echo "Error: Cannot listen for connections\n";
	echo socket_strerror(socket_last_error($sock)); 
	exit(4);
}

// Accept inbound connections
while (($conn = socket_accept($sock)) !== FALSE) {
	if (socket_getpeername($conn, $claddr, $clport)) {
		echo "$claddr connected from port $clport\n";
	} else {
		socket_shutdown($conn);
		socket_close($conn);
		continue;
	}

	$question = socket_read($conn, 8000, PHP_NORMAL_READ);
	if ($question === FALSE) {
		echo "Failed...\n";
		echo "Can't read, terminating...\n";
		socket_shutdown($conn);
		socket_close($conn);
		continue;
	}
	
	$cleanq = trim($question);

	if (!filter_var($cleanq, FILTER_VALIDATE_IP) === false) {
		$ipamapi->execute ("GET", "addresses", array("search", $cleanq), array(), $ipam_token_file);
		$ipamresults = $ipamapi->get_result();
		if ($ipamresults['code'] == 200) {
			$rescnt = count($ipamresults['data']);
			$omsg = "% $rescnt results found\n";
			foreach ($ipamresults['data'] as $res) {
				$omsg .= "\n";
				$omsg .= "ID: " . $res->id . "\n";
				$omsg .= "Subnet ID: " . $res->subnetId . "\n";
				$omsg .= "IP: " . $res->ip . "\n";
				$omsg .= "Hostname: " . $res->hostname . "\n";
				$omsg .= "Desc: " . $res->description . "\n";
				$omsg .= "Changed: " . $res->editDate . "\n";
			}
		} elseif ($ipamresults['code'] == 404) {
			$omsg = "% $cleanq not found\n";
		} else {
			$omsg = "% Unknown response from IPAM\n";
			$omsg = print_r($ipamresults, TRUE);
		}
	} else {
		$omsg = "$question is not a valid IP address";
	}
	$omsg .= "\n% This query was served by $toolname $toolvers at " . date('Y-m-d H:i:s') . "\n";
	if (!socket_send($conn, $omsg, strlen($omsg), MSG_EOR)) {
		echo "Failed...\n";
		echo "Can't write, terminating...\n";
		socket_shutdown($conn);
		socket_close($conn);
		continue;
	}
	socket_shutdown($conn);
	socket_close($conn);
	echo "$claddr completed. Closed.\n";
	continue;
}

?>

