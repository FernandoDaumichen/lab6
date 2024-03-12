<?php

require './ca.php';
require './lib/debug.php';

$publicKey = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjDqMMsCkrsuhfNHuvKVc
XXHbfLHtFocJuVF3nf3ISWE6Vzr03HWo+aSkFeIpUsc95W8YPt9cJ4r2bKXqkd0r
v7PgtBJi5eTjF5nBFZgXa0kKfpG/Xwv1oKk/ITlPa+UMJvs4+BbK1OGoiOZhMM90
LV+8W0mp++FOFrFrRAP86qisaxijz05jaA6hcRUpLpV8Y2nkf6lNA5bNt1fylX3l
9jhNqR/eXrC5aZHduahGei17ItUVJWj+/CGUqXYoxqXQ4wZF707xqDKgrb6+oV1f
89TAAGlywSmDCJ1sNR0TyeBEgW7h8GPG9DUgcTu19K4txx6SphruUmUWA0DyNFoD
LQIDAQAB
-----END PUBLIC KEY-----';

$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

if (!socket_connect($socket, 'localhost', 4443)) {
    echo "Failed to connect to server on port 4443\n";
    exit();
}

echo "Connected to server on port 4443\n";


$clientRandom = bin2hex(random_bytes(32));
socket_write($socket, $clientRandom, strlen($clientRandom));


$serverRandom = socket_read($socket, 64);
$serverCertificate = socket_read($socket, 108);


$ca = new CertificateAuthority();
if (!$ca->validateCertificate('server.php', $serverCertificate)) {
    echo "Invalid server certificate\n";
    socket_close($socket);
    exit();
}

$preMasterSecret = bin2hex(random_bytes(48));
openssl_public_encrypt($preMasterSecret, $encryptedPreMasterSecret, $publicKey);
socket_write($socket, $encryptedPreMasterSecret, strlen($encryptedPreMasterSecret));


$masterSecret = hash('sha256', $preMasterSecret . $clientRandom . $serverRandom);
$ready = socket_read($socket, 5);
if ($ready !== "READY") {
    echo "Server is not ready\n";
    socket_close($socket);
    exit();
}

echo "Server is ready\n";

$LEN = 0;
$algo = 'aes-256-cbc';
$iv = '0f898e31ec73e4f5'; // initialization vector, created using openssl_random_pseudo_bytes(openssl_cipher_iv_length($algo))

while (true) {

    $data = readline("Enter a message: ");
    $encryptedData = openssl_encrypt($data, $algo, $masterSecret, OPENSSL_RAW_DATA, $iv);
    $encryptedHexData = bin2hex($encryptedData);
    $LEN = strlen($encryptedHexData);

    $lenMessage = "LEN=" . str_pad($LEN, 4, '0', STR_PAD_LEFT);
    if (socket_write($socket, $lenMessage, strlen($lenMessage)) === 0) {
        echo "Failed to send encrypted message length\n";
        socket_close($socket);
        exit();
    }

    $ackMessage = socket_read($socket, 8);
    $ackLength = intval(substr($ackMessage, 4));
    if ($ackLength === $LEN) {
        if (socket_write($socket, $encryptedHexData, strlen($encryptedHexData)) === 0) {
            echo "Failed to send encrypted message\n";
            socket_close($socket);
            exit();
        }
    } else {
        echo "Server did not respond\n";
        socket_close($socket);
        exit();
    }
}

?>