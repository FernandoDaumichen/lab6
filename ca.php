<?php

class CertificateAuthority {
    private string $caPrivateKey = 'e424346f57233280bc30d9c93d36e5b554b2844b3ffdea4e453388aeed3d729e';
    private string $algo = 'aes-256-cbc';
    private string $iv = '0f898e31ec73e4f5';
    private $publicKeys = [
        'server.php' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjDqMMsCkrsuhfNHuvKVc
XXHbfLHtFocJuVF3nf3ISWE6Vzr03HWo+aSkFeIpUsc95W8YPt9cJ4r2bKXqkd0r
v7PgtBJi5eTjF5nBFZgXa0kKfpG/Xwv1oKk/ITlPa+UMJvs4+BbK1OGoiOZhMM90
LV+8W0mp++FOFrFrRAP86qisaxijz05jaA6hcRUpLpV8Y2nkf6lNA5bNt1fylX3l
9jhNqR/eXrC5aZHduahGei17ItUVJWj+/CGUqXYoxqXQ4wZF707xqDKgrb6+oV1f
89TAAGlywSmDCJ1sNR0TyeBEgW7h8GPG9DUgcTu19K4txx6SphruUmUWA0DyNFoD
LQIDAQAB
-----END PUBLIC KEY-----'
    ];
    
    public function getSSLCertificate($hashedPublicKey) {
        $encryptedCertificate = openssl_encrypt($hashedPublicKey, $this->algo, $this->caPrivateKey, 0, $this->iv);
        return $encryptedCertificate;
    }

    public function validateCertificate($server, $certificate) {
        $hashedPublicKey = hash('sha256', $this->publicKeys[$server]);
        $decryptedCertificate = openssl_decrypt($certificate, $this->algo, $this->caPrivateKey, 0, $this->iv);
        return $hashedPublicKey === $decryptedCertificate;
    }
}

?>