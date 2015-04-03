<?php
namespace XmlSecLibs;

class XmlSecurityDsigTest extends \PHPUnit_Framework_TestCase
{
    public function testSignC14Comments()
    {
        $xml = "<ApplicationRequest xmlns=\"http://example.org/xmldata/\"><CustomerId>12345678</CustomerId>"
               . "<Command>GetUserInfo</Command><Timestamp>1317032524</Timestamp><Status>ALL</Status>"
               . "<Environment>DEVELOPMENT</Environment><SoftwareId>ExampleApp 0.1\b</SoftwareId>"
               . "<FileType>ABCDEFG</FileType></ApplicationRequest>";

        $doc                     = new \DOMDocument();
        $doc->formatOutput       = false;
        $doc->preserveWhiteSpace = false;
        $doc->loadXML($xml);

        $objDSig = new XMLSecurityDSig();

        $objDSig->setCanonicalMethod(XMLSecurityDSig::C14N_COMMENTS);

        $objDSig->addReference($doc, XMLSecurityDSig::SHA1, array(
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            XMLSecurityDSig::C14N_COMMENTS
        ));

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        /* load private key */
        $objKey->loadKey(dirname(__FILE__) . '/../privkey.pem', true);

        $objDSig->sign($objKey, $doc->documentElement);

        /* Add associated public key */
        $objDSig->add509Cert(file_get_contents(dirname(__FILE__) . '/../mycert.pem'));

        $objDSig->appendSignature($doc->documentElement);

        $sign_output     = $doc->saveXML();
        $sign_output_def = file_get_contents(dirname(__FILE__) . '/../sign-c14-comments.res');
        $this->assertEquals($sign_output_def, $sign_output, "Signature doesn't match");
    }

    public function testSignEmptyUri()
    {
        $doc = new \DOMDocument();
        $doc->load(dirname(__FILE__) . '/../basic-doc.xml');

        $objDSig = new XMLSecurityDSig();

        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'), array('force_uri' => true));

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        /* load private key */
        $objKey->loadKey(dirname(__FILE__) . '/../privkey.pem', true);

        /* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */


        $objDSig->sign($objKey);

        /* Add associated public key */
        $objDSig->add509Cert(file_get_contents(dirname(__FILE__) . '/../mycert.pem'));

        $objDSig->appendSignature($doc->documentElement);

        $sign_output     = $doc->saveXML();
        $sign_output_def = file_get_contents(dirname(__FILE__) . '/../sign-empty-uri.res');
        $this->assertEquals($sign_output_def, $sign_output, "Signature doesn't match");
    }

    public function testWithCommentEmptyUri()
    {
        $doc = new \DOMDocument();
        $doc->load(dirname(__FILE__) . '/../withcomment-empty-uri.xml');

        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($doc);
        $this->assertInstanceOf('\\DomElement', $objDSig, "Cannot locate Signature Node");

        $retVal = $objXMLSecDSig->validateReference();
        $this->assertTrue($retVal, "Reference Validation Failed");

        /*
         * Since we are testing reference canonicalization, we don't need to
         * do more than reference validation here.
         */
    }

    public function testWithCommentIdUri()
    {
        $doc = new \DOMDocument();
        $doc->load(dirname(__FILE__) . '/../withcomment-id-uri.xml');
        $objXMLSecDSig         = new XMLSecurityDSig();
        $objXMLSecDSig->idKeys = array('xml:id');

        $objDSig = $objXMLSecDSig->locateSignature($doc);
        $this->assertInstanceOf('\\DomElement', $objDSig, "Cannot locate Signature Node");

        $retVal = $objXMLSecDSig->validateReference();
        $this->assertTrue($retVal, "Reference Validation Failed");

        /*
         * Since we are testing reference canonicalization, we don't need to
         * do more than reference validation here.
         */
    }

    public function testXmlSign()
    {
        $doc = new \DOMDocument();
        $doc->load(dirname(__FILE__) . '/../basic-doc.xml');

        $objDSig = new XMLSecurityDSig();

        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $objDSig->addReference($doc, XMLSecurityDSig::SHA1, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        /* load private key */
        $objKey->loadKey(dirname(__FILE__) . '/../privkey.pem', true);

        /* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */


        $objDSig->sign($objKey);

        /* Add associated public key */
        $objDSig->add509Cert(file_get_contents(dirname(__FILE__) . '/../mycert.pem'));

        $objDSig->appendSignature($doc->documentElement);

        $sign_output     = $doc->saveXML();
        $sign_output_def = file_get_contents(dirname(__FILE__) . '/../sign-basic-test.res');
        $this->assertEquals($sign_output_def, $sign_output, "Signature doesn't match");
    }

    public function testXmlSign_SHA256_RSA_SHA256()
    {
        $doc = new \DOMDocument();
        $doc->load(dirname(__FILE__) . '/../basic-doc.xml');

        $objDSig = new XMLSecurityDSig();

        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        $objDSig->addReference($doc, XMLSecurityDSig::SHA256, array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'));

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
        /* load private key */
        $objKey->loadKey(dirname(__FILE__) . '/../privkey.pem', true);

        /* if key has Passphrase, set it using $objKey->passphrase = <passphrase> " */

        $objDSig->sign($objKey);

        /* Add associated public key */
        $objDSig->add509Cert(file_get_contents(dirname(__FILE__) . '/../mycert.pem'));
        $objDSig->appendSignature($doc->documentElement);

        $sign_output     = $doc->saveXML();
        $sign_output_def = file_get_contents(dirname(__FILE__) . '/../sign-sha256-rsa-sha256-test.res');
        $this->assertEquals($sign_output_def, $sign_output, "Signature doesn't match");
    }


}