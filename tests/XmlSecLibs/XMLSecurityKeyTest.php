<?php

namespace XmlSecLibs;

class XMLSecurityKeyTest extends \PHPUnit_Framework_TestCase
{
    public function testGenerateSessionKeyBasics()
    {
        $key = new XMLSecurityKey(XMLSecurityKey::TRIPLEDES_CBC);
        $k = $key->generateSessionKey();
        $this->assertEquals($key->key, $k, 'Return value does not match generated key.');

        $keysizes = [
            XMLSecurityKey::TRIPLEDES_CBC => 24,
            XMLSecurityKey::AES128_CBC    => 16,
            XMLSecurityKey::AES192_CBC    => 24,
            XMLSecurityKey::AES256_CBC    => 32,
        ];

        foreach ($keysizes as $type => $keysize) {
            $key = new XMLSecurityKey($type);
            $k = $key->generateSessionKey();
            $this->assertEquals(
                $keysize,
                strlen($k),
                sprintf('Invalid keysize for key type %s. Was %d, should have been %d.', $type, strlen($k), $keysize)
            );
        }
    }

    public function testGenerateSessionKeyParity()
    {
        /* Run the test several times, to increase the chance of detecting an error. */
        for ($t = 0; $t < 16; $t++) {
            $key = new XMLSecurityKey(XMLSecurityKey::TRIPLEDES_CBC);
            $k = $key->generateSessionKey();

            for ($i = 0; $i < strlen($k); $i++) {
                $byte = ord($k[ $i ]);
                $parity = 0;
                while ($byte !== 0) {
                    $parity ^= $byte & 1;
                    $byte >>= 1;
                }
                $this->assertEquals(1, $parity);
            }
        }
    }

    public function symmetricKeySizeProvider()
    {
        return [
            [XMLSecurityKey::TRIPLEDES_CBC, 24],
            [XMLSecurityKey::AES128_CBC, 16],
            [XMLSecurityKey::AES192_CBC, 24],
            [XMLSecurityKey::AES256_CBC, 32],
        ];
    }

    /**
     * @dataProvider symmetricKeySizeProvider
     */
    public function testGetSymmetricKeySize($keyType, $keySize)
    {
        $key = new XMLSecurityKey($keyType);
        $size = $key->getSymmetricKeySize();
        $this->assertEquals(
            $keySize,
            $size,
            sprintf('Invalid keysize for key type %s. Was %d, should have been %d.', $keyType, $size, $keySize)
        );
    }

    public function testThumbPrint()
    {
        $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, ['type' => 'public']);
        $siteKey->loadKey(dirname(__FILE__).'/../mycert.pem', true, true);

        $thumbprint = $siteKey->getX509Thumbprint();
        $this->assertEquals('8b600d9155e8e8dfa3c10998f736be086e83ef3b', $thumbprint, "Thumbprint doesn't match");
        $this->assertEquals('OGI2MDBkOTE1NWU4ZThkZmEzYzEwOTk4ZjczNmJlMDg2ZTgzZWYzYg==', base64_encode($thumbprint), "Base64 Thumbprint doesn't match");
    }
}
