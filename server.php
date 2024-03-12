<?php

require './ca.php';
require './lib/debug.php';

$privateKey = '-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCMOowywKSuy6F8
0e68pVxdcdt8se0Whwm5UXed/chJYTpXOvTcdaj5pKQV4ilSxz3lbxg+31wnivZs
peqR3Su/s+C0EmLl5OMXmcEVmBdrSQp+kb9fC/WgqT8hOU9r5Qwm+zj4FsrU4aiI
5mEwz3QtX7xbSan74U4WsWtEA/zqqKxrGKPPTmNoDqFxFSkulXxjaeR/qU0Dls23
V/KVfeX2OE2pH95esLlpkd25qEZ6LXsi1RUlaP78IZSpdijGpdDjBkXvTvGoMqCt
vr6hXV/z1MAAaXLBKYMInWw1HRPJ4ESBbuHwY8b0NSBxO7X0ri3HHpKmGu5SZRYD
QPI0WgMtAgMBAAECggEAExcdYwNq6Aj80RtbXv88FdScRtuKJVj47+uxVybnj2XX
JWz3TNQPzvylAf2qFoTdXlDDgjuyNgfrCFuGFZmAjTaVzq36HMYOTHY4HRJ5jbeB
4D1DSlM8e0TPPVyp/UxPXTcySEQCFP0rjoeej6COdmbkI6FhrNK9aMV6juXkFqXw
RijJoAckI19loZqDh2weWGza9io/p1AmRs8FWBCkjIFXPjJ0B5d06IyQRq0SYPku
FsyZLauSay2ftVtfP/wqXDYWAk3IZegBNMu8LdhJH8Hct2Zr1k4bE4yZirCvUFa/
ml9hRGsXYUMDZgSaR910ZyQzZS0ua8a6oK3eR1ec2QKBgQC3rdeZby9ctU5qRuEO
ZJ8/ZPuWKk9qyq1wc73Mie2p7A+65qUuXAQn3YqXbcWQxn3BQKX5YGMdA9rPuhxu
1UOvGyOeYnNDrPQSiCaSTM6iQ+jhMTY8p/PqwXA3z3x7F/OKg9jA9KZv7a796hW+
J9JuezToyC9n8NKo81IpmAUiowKBgQDDcRJy95lPvHZjUtQuA9/r8utPkQ4ySedP
aBAD++W478OUqqw0kkTqJrMQuDEvEo78R644ObmdJGe9rRiEpkgRlkp1ulBiEX+o
Hq5aicx19AKyTH+6o8x7Ir7ghMgT/RlROoCejNvuvpuUENFfQRK3MB7YXhq1PPvj
7RXHXu5v7wKBgQCstCtVHGLnA56wdOaltty5KcUY4716hwlfA6TBTisGK2x66uUD
WweZSEhIq7EouEmDzLqCaSuoG3jA+phDagjS+2yZPq5sQpHXXucNhmR/0+SC4NfD
XpQM9kcCYvgDcXjPk7rZau+XrF9uZYx+GElXEkekXJ2eWKRqsSZe745ciwKBgBep
1iEDZ5Wm7PKjsbsMjw0jcWhF2OEv34jWwbGpyyu0JAsZCxamax+qpd2tX48igRt8
llSKcLXdFY56qdBNzcYLW2Kbt2XYVouFg3jE3HOfor/x0TlI4dY647+NdCgvaeRS
4AXSakKi43Vu/9q3p0t00RdDdZpiEuGK8CsejGITAoGASn41HcGtAVD+UT7YYKOg
puPedHiM8zsazRY7/EHyvDjiSuyyJyoC/tUsS24CbgxY24JrMmhfPufXRcdLVAp7
of8xRXg8qkbyQDTavs1D+ripXzPkW7BM1kZolkNzfqUFgkwKzm4D0fgYKITl9RFi
gXDVOMiTscTiSLW/KaHWUTg=
-----END PRIVATE KEY-----';

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

if (!socket_bind($socket, '0.0.0.0', 4443)) {
    echo "Failed to bind socket to port 4443\n";
    exit();
}

socket_listen($socket);

echo "Server listening on port 4443\n";

$client = socket_accept($socket);

echo "Client connected\n";


$clientRandom = socket_read($client, 64);


$serverRandom = bin2hex(random_bytes(32));
socket_write($client, $serverRandom, strlen($serverRandom));


$ca = new CertificateAuthority();
$hashedPublicKey = hash('sha256', $publicKey);
$certificate = $ca->getSSLCertificate($hashedPublicKey);
socket_write($client, $certificate, strlen($certificate));


$preMasterSecret = socket_read($client, 304);


openssl_private_decrypt($preMasterSecret, $decryptedPreMasterSecret, $privateKey);

$masterSecret = hash('sha256', $decryptedPreMasterSecret . $clientRandom . $serverRandom);
socket_write($client, "READY", 5);


$algo = 'aes-256-cbc'; // encryption algorithm
$iv = '0f898e31ec73e4f5'; // initialization vector

while (true) {
    echo "Server waiting for data\n";

  
    $lenMessage = socket_read($client, 8);
    $len = intval(substr($lenMessage, 4));
    if ($len === 0) {
        socket_close($client);
        exit();
    }
    socket_write($client, "ACK=" . str_pad($len, 4, '0', STR_PAD_LEFT));

   
    $encryptedData = socket_read($client, $len);
    $binaryData = hex2bin($encryptedData);

    $decryptedData = openssl_decrypt($binaryData, $algo, $masterSecret, OPENSSL_RAW_DATA, $iv);
    echo $decryptedData . "\n";
}

?>