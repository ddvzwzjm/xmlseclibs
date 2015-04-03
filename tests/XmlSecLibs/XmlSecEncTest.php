<?php
namespace XmlSecLibs;

/**
 * Class XmlSecEncTest
 * @package XmlSecLibs
 */
class XmlSecEncTest extends \PHPUnit_Framework_TestCase
{
    /**
     *
     */
    public function testSomething()
    {
        $this->assertTrue(true);
    }

    /**
     * @throws \Exception
     */
    public function testEncryptedDataNodeOrder()
    {
        $dom = new \DOMDocument();
        $dom->load(dirname(__FILE__) . '/../basic-doc.xml');

        $objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $objKey->generateSessionKey();

        $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
        $siteKey->loadKey(dirname(__FILE__) . '/../mycert.pem', true, true);

        $enc = new XMLSecEnc();
        $enc->setNode($dom->documentElement);
        $enc->encryptKey($siteKey, $objKey);

        $enc->type = XMLSecEnc::Content;
        $encNode   = $enc->encryptNode($objKey);

        $nodeOrder = array(
            'EncryptionMethod',
            'KeyInfo',
            'CipherData',
            'EncryptionProperties',
        );

        $prevNode = 0;
        for ($node = $encNode->firstChild; $node !== null; $node = $node->nextSibling) {
            if (!( $node instanceof \DOMElement )) {
                /* Skip comment and text nodes. */
                continue;
            }

            $name = $node->localName;

            $cIndex = array_search($name, $nodeOrder, true);
            if ($cIndex === false) {
                $this->fail("Unknown node: $name");
            }
            $this->assertGreaterThanOrEqual($prevNode, $cIndex);
            if ($cIndex >= $prevNode) {
                /* In correct order. */
                $prevNode = $cIndex;
                continue;
            }

            $prevName = $nodeOrder[ $prevNode ];
            $this->fail("Incorrect order: $name must appear before $prevName");
        }
    }

    /**
     * @throws \Exception
     */
    public function testGetCipherData()
    {
        $doc = new \DOMDocument();
        $doc->load(dirname(__FILE__) . '/../oaep_sha1-res.xml');


        $objenc  = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($doc);
        $objenc->setNode($encData);

        $ciphervalue = $objenc->getCipherValue();
        $this->assertEquals('e3b188c5a139655d14d3f7a1e6477bc3', md5($ciphervalue));


        $objKey       = $objenc->locateKey();
        $objKeyInfo   = $objenc->locateKeyInfo($objKey);
        $encryptedKey = $objKeyInfo->encryptedCtx;

        $keyCV = $encryptedKey->getCipherValue();
        $this->assertEquals('b36f81645cb068dd59d69c7ff96e835a', md5($keyCV));
    }

    /**
     *
     */
    public function testRetrievalMethodFindKey()
    {
        $doc = new \DOMDocument();
        $doc->load(dirname(__FILE__) . "/../retrievalmethod-findkey.xml");

        $objenc  = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($doc);
        $this->assertNotEmpty($encData, "Cannot locate Encrypted Data");

        $objenc->setNode($encData);
        $objenc->type = $encData->getAttribute("Type");
        $objKey       = $objenc->locateKey();

        $objKeyInfo = $objenc->locateKeyInfo($objKey);

        $this->assertTrue($objKeyInfo->isEncrypted, 'Expected $objKeyInfo to refer to an encrypted key by now.');
    }


    /**
     * @return array
     */
    public function decryptFilesProvider()
    {
        return array(
            array(
                'AOESP_SHA1',
                dirname(__FILE__) . '/../oaep_sha1-res.xml',
                dirname(__FILE__) . "/../privkey.pem"
            ),
            array(
                'AOESP_SHA1_CONTENT',
                dirname(__FILE__) . '/../oaep_sha1-content-res.xml',
                dirname(__FILE__) . "/../privkey.pem"
            )
        );
    }

    /**
     *
     * @@dataProvider decryptFilesProvider
     * @throws \Exception
     */
    public function testDecrypt($testName, $testFile, $privKey)
    {
        $doc    = new \DOMDocument();
        $output = null;
        $doc->load($testFile);

        $objenc  = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($doc);
        $this->assertInstanceOf('\\DOMElement', $encData, "Cannot locate Encrypted Data");

        $objenc->setNode($encData);
        $objenc->type = $encData->getAttribute("Type");
        $objKey       = $objenc->locateKey();
        $this->assertInstanceOf('\\XmlSecLibs\\XMLSecurityKey', $objKey, "We know the secret key, but not the algorithm");

        $key = null;

        if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
            if ($objKeyInfo->isEncrypted) {
                $objencKey = $objKeyInfo->encryptedCtx;
                $objKeyInfo->loadKey($privKey, true);
                $key = $objencKey->decryptKey($objKeyInfo);
            }
        }

        if (!$objKey->key && empty( $key )) {
            $objKeyInfo->loadKey($privKey, true);
        }
        if (empty( $objKey->key )) {
            $objKey->loadKey($key);
        }

        $token = null;

        if ($decrypt = $objenc->decryptNode($objKey, true)) {
            $output = null;
            if ($decrypt instanceof \DOMNode) {
                if ($decrypt instanceof \DOMDocument) {
                    $output = $decrypt->saveXML();
                }
                else {
                    $output = $decrypt->ownerDocument->saveXML();
                }
            }
            else {
                $output = $decrypt;
            }
        }

        $outfile = dirname(__FILE__) . "/../basic-doc.xml";
        $res     = null;
        $this->assertFileExists($outfile);

        $resDoc = new \DOMDocument();
        $resDoc->load($outfile);
        $res = $resDoc->saveXML();
        $this->assertEquals($res, $output, "$testName Failed to decrypt $testFile");
    }

    /**
     * @return array
     */
    public function encryptProvider()
    {
        return array(
            array(XMLSecEnc::Element, 'EncryptedData'),
            array(XMLSecEnc::Content, 'Root')
        );
    }

    /**
     * @dataProvider encryptProvider
     *
     */
    public function testEncrypt($encType, $rootLocalName)
    {
        $dom = new \DOMDocument();
        $dom->load(dirname(__FILE__) . '/../basic-doc.xml');

        $objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $objKey->generateSessionKey();

        $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
        $siteKey->loadKey(dirname(__FILE__) . '/../mycert.pem', true, true);

        $enc = new XMLSecEnc();
        $enc->setNode($dom->documentElement);
        $enc->encryptKey($siteKey, $objKey);

        $enc->type = $encType;
        $enc->encryptNode($objKey);

        $root = $dom->documentElement;
        $this->assertEquals($rootLocalName, $root->localName, "Failed to encrypt data");
    }

    /**
     * @throws \Exception
     */
    public function testEncryptNoReplace()
    {
        $dom = new \DOMDocument();
        $dom->load(dirname(__FILE__) . '/../basic-doc.xml');

        $origData = $dom->saveXML();

        $objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $objKey->generateSessionKey();

        $siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
        $siteKey->loadKey(dirname(__FILE__) . '/../mycert.pem', true, true);

        $enc = new XMLSecEnc();
        $enc->setNode($dom->documentElement);
        $enc->encryptKey($siteKey, $objKey);

        $enc->type = XMLSecEnc::Element;
        $encNode   = $enc->encryptNode($objKey, false);

        $newData = $dom->saveXML();
        $this->assertEquals($origData, $newData, "Original data was modified");
        $this->assertFalse(
            $encNode->namespaceURI !== XMLSecEnc::XMLENCNS || $encNode->localName !== 'EncryptedData',
            "Encrypted node wasn't a <xenc:EncryptedData>-element"
        );
    }

    /**
     * @return array
     */
    public function verifyProvider()
    {
        return array(
            /* [$testName, $testFile] */
            array('SIGN_TEST', dirname(__FILE__) . '/../sign-basic-test.xml'),
            // ['SIGN_TEST_RSA_SHA256', dirname(__FILE__) . '/../sign-sha256-rsa-sha256-test.xml'] // There is no such file in tests folder
        );
    }

    /**
     * @param $testName
     * @param $testFile
     *
     * @dataProvider verifyProvider
     */
    public function testVerify($testName, $testFile)
    {
        $doc = new \DOMDocument();

        $doc->load($testFile);
        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($doc);
        $this->assertInstanceOf('\\DOMElement', $objDSig, "Cannot locate Signature Node");

        $objXMLSecDSig->canonicalizeSignedInfo();
        $objXMLSecDSig->idKeys = array('wsu:Id');
        $objXMLSecDSig->idNS   = array('wsu' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');

        $retVal = $objXMLSecDSig->validateReference();

        $this->assertTrue($retVal, "Reference Validation Failed");

        $objKey = $objXMLSecDSig->locateKey();
        $this->assertInstanceOf('\\XmlSecLibs\\XMLSecurityKey', $objKey, "We have no idea about the key");

        $key = null;

        $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

        if (!$objKeyInfo->key && empty( $key )) {
            $objKey->loadKey(dirname(__FILE__) . '/../mycert.pem', true);
        }

        $this->assertEquals(1, $objXMLSecDSig->verify($objKey), "$testName: Signature is invalid");
    }
}