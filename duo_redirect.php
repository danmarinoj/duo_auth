<?php

use Duo\DuoUniversal\Client;

$query_params = array();
parse_str($_SERVER['QUERY_STRING'], $query_params);

# initialize client
$config = parse_ini_file("plugins/duo_auth/duo.conf");

try {
    $duo_client = new Client(
        $config['client_id'],
        $config['client_secret'],
        $config['api_hostname'],
        $config['redirect_uri']
    );
} catch (DuoException $e) {
    throw new ErrorException("*** Duo config error. Verify the values in duo.conf are correct ***\n" . $e->getMessage());
}

# Check for errors from the Duo authentication
if (isset($query_params["error"])) {
    $error_msg = $query_params["error"] . ":" . $query_params["error_description"];
    $logger->error($error_msg);
    $response->getBody()->write("Got Error: " . $error_msg);
    return null;
}

# Get authorization token to trade for 2FA
$code = $query_params["duo_code"];

# Get state to verify consistency and originality
$state = $query_params["state"];

# Retrieve the previously stored state and username from the session
$saved_state = $_SESSION["state"];
$username = $_SESSION["username"];
unset($_SESSION["state"]);
unset($_SESSION["username"]);

if (empty($saved_state) || empty($username)) {
    return null;
}

# Ensure nonce matches from initial request
if ($state != $saved_state) {
    $args["message"] = "Duo state does not match saved state";
    return null;
}

try {
    $decoded_token = $duo_client->exchangeAuthorizationCodeFor2FAResult($code, $username);
} catch (DuoException $e) {
    $logger->error($e->getMessage());
    // Error decoding Duo result. Confirm device clock is correct
    return null;
}

return "success";
