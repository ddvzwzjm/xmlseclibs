<?php
/**
 * xmlseclibs.php
 *
 * Copyright (c) 2007-2015, Robert Richards <rrichards@cdatazone.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Robert Richards nor the names of his
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @author     Robert Richards <rrichards@cdatazone.org>
 * @copyright  2007-2015 Robert Richards <rrichards@cdatazone.org>
 * @license    http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @version    1.3.2-dev
 */

namespace XmlSecLibs;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use Exception;

/**
 * Class XMLSecurityDSig
 * @package XmlSecLibs
 */
class XMLSecurityDSig
{
    const XMLDSIGNS = 'http://www.w3.org/2000/09/xmldsig#';
    const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
    const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';
    const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';
    const template = '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:SignatureMethod />
  </ds:SignedInfo>
</ds:Signature>';

    /**
     * @var DOMElement|null
     */
    public $sigNode = null;
    /**
     * @var array
     */
    public $idKeys = array();
    /**
     * @var array
     */
    public $idNS = array();
    /**
     * @var null
     */
    private $signedInfo = null;
    /**
     * @var null
     */
    private $xPathCtx = null;
    /**
     * @var null
     */
    private $canonicalMethod = null;
    /**
     * @var string
     */
    private $prefix = 'ds';
    /**
     * @var string
     */
    private $searchpfx = 'secdsig';

    /* This variable contains an associative array of validated nodes. */
    /**
     * @var null
     */
    private $validatedNodes = null;

    /**
     *
     */
    public function __construct()
    {
        $sigdoc = new DOMDocument();
        $sigdoc->loadXML(XMLSecurityDSig::template);
        $this->sigNode = $sigdoc->documentElement;
    }


    /**
     *
     */
    private function resetXPathObj()
    {
        $this->xPathCtx = null;
    }

    /**
     * @return DOMXPath|null
     */
    private function getXPathObj()
    {
        if (empty( $this->xPathCtx ) && !empty( $this->sigNode )) {
            $xpath = new DOMXPath($this->sigNode->ownerDocument);
            $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
            $this->xPathCtx = $xpath;
        }

        return $this->xPathCtx;
    }

    /**
     * @param string $prefix
     *
     * @return string
     */
    static function generate_GUID($prefix = 'pfx')
    {
        $uuid = md5(uniqid(rand(), true));
        $guid = $prefix . substr($uuid, 0, 8) . "-" .
                substr($uuid, 8, 4) . "-" .
                substr($uuid, 12, 4) . "-" .
                substr($uuid, 16, 4) . "-" .
                substr($uuid, 20, 12);

        return $guid;
    }

    /**
     * @param $objDoc
     *
     * @return DOMElement|DOMNode|null
     */
    public function locateSignature($objDoc)
    {
        if ($objDoc instanceof DOMDocument) {
            $doc = $objDoc;
        }
        else {
            $doc = $objDoc->ownerDocument;
        }
        if ($doc) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
            $query         = ".//secdsig:Signature";
            $nodeset       = $xpath->query($query, $objDoc);
            $this->sigNode = $nodeset->item(0);

            return $this->sigNode;
        }

        return null;
    }

    /**
     * @param $name
     * @param null $value
     *
     * @return DOMElement
     */
    public function createNewSignNode($name, $value = null)
    {
        $doc = $this->sigNode->ownerDocument;
        if (!is_null($value)) {
            $node = $doc->createElementNS(XMLSecurityDSig::XMLDSIGNS, $this->prefix . ':' . $name, $value);
        }
        else {
            $node = $doc->createElementNS(XMLSecurityDSig::XMLDSIGNS, $this->prefix . ':' . $name);
        }

        return $node;
    }

    /**
     * @param $method
     *
     * @throws Exception
     */
    public function setCanonicalMethod($method)
    {
        switch ($method) {
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
            case 'http://www.w3.org/2001/10/xml-exc-c14n#':
            case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
                $this->canonicalMethod = $method;
                break;
            default:
                throw new Exception('Invalid Canonical Method');
        }
        if ($xpath = $this->getXPathObj()) {
            $query   = './' . $this->searchpfx . ':SignedInfo';
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($sinfo = $nodeset->item(0)) {
                $query   = './' . $this->searchpfx . 'CanonicalizationMethod';
                $nodeset = $xpath->query($query, $sinfo);
                if (!( $canonNode = $nodeset->item(0) )) {
                    $canonNode = $this->createNewSignNode('CanonicalizationMethod');
                    $sinfo->insertBefore($canonNode, $sinfo->firstChild);
                }
                $canonNode->setAttribute('Algorithm', $this->canonicalMethod);
            }
        }
    }

    /**
     * @param DOMNode $node
     * @param $canonicalMethod
     * @param null $arXPath
     * @param null $prefixList
     *
     * @return string
     */
    private function canonicalizeData(DOMNode $node, $canonicalMethod, $arXPath = null, $prefixList = null)
    {
        $exclusive    = false;
        $withComments = false;
        switch ($canonicalMethod) {
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
                $exclusive    = false;
                $withComments = false;
                break;
            case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
                $withComments = true;
                break;
            case 'http://www.w3.org/2001/10/xml-exc-c14n#':
                $exclusive = true;
                break;
            case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':
                $exclusive    = true;
                $withComments = true;
                break;
        }

        if (
            is_null($arXPath) &&
            ($node instanceof DOMNode) &&
            ($node->ownerDocument !== null) &&
            $node->isSameNode($node->ownerDocument->documentElement)
        ) {
            /* Check for any PI or comments as they would have been excluded */
            $element = $node;
            while ($refnode = $element->previousSibling) {
                if ($refnode->nodeType == XML_PI_NODE || (($refnode->nodeType == XML_COMMENT_NODE) && $withComments)) {
                    break;
                }
                $element = $refnode;
            }
            if ($refnode == null) {
                $node = $node->ownerDocument;
            }
        }

        return $node->C14N($exclusive, $withComments, $arXPath, $prefixList);
    }

    /**
     * @return null|string
     */
    public function canonicalizeSignedInfo()
    {
        $doc             = $this->sigNode->ownerDocument;
        $canonicalMethod = null;
        if ($doc) {
            $xpath   = $this->getXPathObj();
            $query   = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($signInfoNode = $nodeset->item(0)) {
                $query   = "./secdsig:CanonicalizationMethod";
                $nodeset = $xpath->query($query, $signInfoNode);
                /** @var DOMElement $canonNode */
                if ($canonNode = $nodeset->item(0)) {
                    $canonicalMethod = $canonNode->getAttribute('Algorithm');
                }
                $this->signedInfo = $this->canonicalizeData($signInfoNode, $canonicalMethod);

                return $this->signedInfo;
            }
        }

        return null;
    }

    /**
     * @param $digestAlgorithm
     * @param $data
     *
     * @return string
     * @throws Exception
     */
    public function calculateDigest($digestAlgorithm, $data)
    {
        switch ($digestAlgorithm) {
            case XMLSecurityDSig::SHA1:
                $alg = 'sha1';
                break;
            case XMLSecurityDSig::SHA256:
                $alg = 'sha256';
                break;
            case XMLSecurityDSig::SHA384:
                $alg = 'sha384';
                break;
            case XMLSecurityDSig::SHA512:
                $alg = 'sha512';
                break;
            case XMLSecurityDSig::RIPEMD160:
                $alg = 'ripemd160';
                break;
            default:
                throw new Exception("Cannot validate digest: Unsupported Algorith <$digestAlgorithm>");
        }
        if (function_exists('hash')) {
            return base64_encode(hash($alg, $data, true));
        }
        elseif (function_exists('mhash')) {
            $alg = "MHASH_" . strtoupper($alg);

            return base64_encode(mhash(constant($alg), $data));
        }
        elseif ($alg === 'sha1') {
            return base64_encode(sha1($data, true));
        }
        else {
            throw new Exception('xmlseclibs is unable to calculate a digest. Maybe you need the mhash library?');
        }
    }

    /**
     * @param $refNode
     * @param $data
     *
     * @return bool
     * @throws Exception
     */
    public function validateDigest($refNode, $data)
    {
        $xpath = new DOMXPath($refNode->ownerDocument);
        $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
        $query           = 'string(./secdsig:DigestMethod/@Algorithm)';
        $digestAlgorithm = $xpath->evaluate($query, $refNode);
        $digValue        = $this->calculateDigest($digestAlgorithm, $data);
        $query           = 'string(./secdsig:DigestValue)';
        $digestValue     = $xpath->evaluate($query, $refNode);

        return ( $digValue == $digestValue );
    }

    /**
     * @param $refNode
     * @param $objData
     * @param bool $includeCommentNodes
     *
     * @return string
     */
    public function processTransforms($refNode, $objData, $includeCommentNodes = true)
    {
        $data  = $objData;
        $xpath = new DOMXPath($refNode->ownerDocument);
        $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
        $query           = './secdsig:Transforms/secdsig:Transform';
        $nodelist        = $xpath->query($query, $refNode);
        $canonicalMethod = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
        $arXPath         = null;
        $prefixList      = null;
        /** @var DomElement $transform */
        foreach ($nodelist AS $transform) {
            $algorithm = $transform->getAttribute("Algorithm");
            switch ($algorithm) {
                case 'http://www.w3.org/2001/10/xml-exc-c14n#':
                case 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments':

                    if (!$includeCommentNodes) {
                        /* We remove comment nodes by forcing it to use a canonicalization
                         * without comments.
                         */
                        $canonicalMethod = 'http://www.w3.org/2001/10/xml-exc-c14n#';
                    }
                    else {
                        $canonicalMethod = $algorithm;
                    }

                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName == 'InclusiveNamespaces') {
                            if ($pfx = $node->getAttribute('PrefixList')) {
                                $arpfx   = array();
                                $pfxlist = explode(" ", $pfx);
                                foreach ($pfxlist AS $pfx) {
                                    $val = trim($pfx);
                                    if (!empty( $val )) {
                                        $arpfx[] = $val;
                                    }
                                }
                                if (count($arpfx) > 0) {
                                    $prefixList = $arpfx;
                                }
                            }
                            break;
                        }
                        $node = $node->nextSibling;
                    }
                    break;
                case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315':
                case 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments':
                    if (!$includeCommentNodes) {
                        /* We remove comment nodes by forcing it to use a canonicalization
                         * without comments.
                         */
                        $canonicalMethod = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
                    }
                    else {
                        $canonicalMethod = $algorithm;
                    }

                    break;
                case 'http://www.w3.org/TR/1999/REC-xpath-19991116':
                    $node = $transform->firstChild;
                    while ($node) {
                        if ($node->localName == 'XPath') {
                            $arXPath               = array();
                            $arXPath['query']      = '(.//. | .//@* | .//namespace::*)[' . $node->nodeValue . ']';
                            $arXpath['namespaces'] = array();
                            $nslist                = $xpath->query('./namespace::*', $node);
                            foreach ($nslist AS $nsnode) {
                                if ($nsnode->localName != "xml") {
                                    $arXPath['namespaces'][ $nsnode->localName ] = $nsnode->nodeValue;
                                }
                            }
                            break;
                        }
                        $node = $node->nextSibling;
                    }
                    break;
            }
        }
        if ($data instanceof DOMNode) {
            $data = $this->canonicalizeData($objData, $canonicalMethod, $arXPath, $prefixList);
        }

        return $data;
    }

    /**
     * @param DOMElement $refNode
     *
     * @return bool
     */
    public function processRefNode(DOMElement $refNode)
    {

        $dataObject = null;

        /*
         * Depending on the URI, we may not want to include comments in the result
         * See: http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel
         */
        $includeCommentNodes = true;

        if ($uri = $refNode->getAttribute("URI")) {
            $arUrl = parse_url($uri);
            if (empty( $arUrl['path'] )) {
                if ($identifier = $arUrl['fragment']) {

                    /* This reference identifies a node with the given id by using
                     * a URI on the form "#identifier". This should not include comments.
                     */
                    $includeCommentNodes = false;

                    $xPath = new DOMXPath($refNode->ownerDocument);
                    if ($this->idNS && is_array($this->idNS)) {
                        foreach ($this->idNS AS $nspf => $ns) {
                            $xPath->registerNamespace($nspf, $ns);
                        }
                    }
                    $iDlist = '@Id="' . $identifier . '"';
                    if (is_array($this->idKeys)) {
                        foreach ($this->idKeys AS $idKey) {
                            $iDlist .= " or @$idKey='$identifier'";
                        }
                    }
                    $query      = '//*[' . $iDlist . ']';
                    $dataObject = $xPath->query($query)->item(0);
                }
                else {
                    $dataObject = $refNode->ownerDocument;
                }
            }
            else {
                $dataObject = file_get_contents($arUrl);
            }
        }
        else {
            /* This reference identifies the root node with an empty URI. This should
             * not include comments.
             */
            $includeCommentNodes = false;

            $dataObject = $refNode->ownerDocument;
        }
        $data = $this->processTransforms($refNode, $dataObject, $includeCommentNodes);
        if (!$this->validateDigest($refNode, $data)) {
            return false;
        }

        if ($dataObject instanceof DOMNode) {
            /* Add this node to the list of validated nodes. */
            if (!empty( $identifier )) {
                $this->validatedNodes[ $identifier ] = $dataObject;
            }
            else {
                $this->validatedNodes[] = $dataObject;
            }
        }

        return true;
    }

    /**
     * @param DOMElement $refNode
     *
     * @return null
     */
    public function getRefNodeID(DOMElement $refNode)
    {
        if ($uri = $refNode->getAttribute("URI")) {
            $arUrl = parse_url($uri);
            if (empty( $arUrl['path'] )) {
                if ($identifier = $arUrl['fragment']) {
                    return $identifier;
                }
            }
        }

        return null;
    }

    /**
     * @return array
     * @throws Exception
     */
    public function getRefIDs()
    {
        $refids = array();

        $xpath   = $this->getXPathObj();
        $query   = "./secdsig:SignedInfo/secdsig:Reference";
        $nodeset = $xpath->query($query, $this->sigNode);
        if ($nodeset->length == 0) {
            throw new Exception("Reference nodes not found");
        }
        foreach ($nodeset AS $refNode) {
            $refids[] = $this->getRefNodeID($refNode);
        }

        return $refids;
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function validateReference()
    {
        $doc = $this->sigNode->ownerDocument;
        if (!$doc->isSameNode($this->sigNode)) {
            $this->sigNode->parentNode->removeChild($this->sigNode);
        }
        $xpath   = $this->getXPathObj();
        $query   = "./secdsig:SignedInfo/secdsig:Reference";
        $nodeset = $xpath->query($query, $this->sigNode);
        if ($nodeset->length == 0) {
            throw new Exception("Reference nodes not found");
        }

        /* Initialize/reset the list of validated nodes. */
        $this->validatedNodes = array();

        foreach ($nodeset AS $refNode) {
            if (!$this->processRefNode($refNode)) {
                /* Clear the list of validated nodes. */
                $this->validatedNodes = null;
                throw new Exception("Reference validation failed");
            }
        }

        return true;
    }

    /**
     * @param DOMElement $sinfoNode
     * @param DOMNode $node
     * @param $algorithm
     * @param null $arTransforms
     * @param null $options
     *
     * @throws Exception
     */
    private function addRefInternal(DOMElement $sinfoNode, DOMNode $node, $algorithm, $arTransforms = null, $options = null)
    {
        $prefix       = null;
        $prefix_ns    = null;
        $id_name      = 'Id';
        $overwrite_id = true;
        $force_uri    = false;

        if (is_array($options)) {
            $prefix       = empty( $options['prefix'] ) ? null : $options['prefix'];
            $prefix_ns    = empty( $options['prefix_ns'] ) ? null : $options['prefix_ns'];
            $id_name      = empty( $options['id_name'] ) ? 'Id' : $options['id_name'];
            $overwrite_id = !isset( $options['overwrite'] ) ? true : (bool) $options['overwrite'];
            $force_uri    = !isset( $options['force_uri'] ) ? false : (bool) $options['force_uri'];
        }

        $attname = $id_name;
        if (!empty( $prefix )) {
            $attname = $prefix . ':' . $attname;
        }

        $refNode = $this->createNewSignNode('Reference');
        $sinfoNode->appendChild($refNode);

        if (!$node instanceof DOMDocument) {
            /** @var DOMElement $node */
            $uri = null;
            if (!$overwrite_id) {
                $uri = $node->getAttributeNS($prefix_ns, $id_name);
            }
            if (empty( $uri )) {
                $uri = XMLSecurityDSig::generate_GUID();
                $node->setAttributeNS($prefix_ns, $attname, $uri);
            }
            $refNode->setAttribute("URI", '#' . $uri);
        }
        elseif ($force_uri) {
            $refNode->setAttribute("URI", '');
        }

        $transNodes = $this->createNewSignNode('Transforms');
        $refNode->appendChild($transNodes);

        if (is_array($arTransforms)) {
            foreach ($arTransforms AS $transform) {
                $transNode = $this->createNewSignNode('Transform');
                $transNodes->appendChild($transNode);
                if (is_array($transform) &&
                    ( !empty( $transform['http://www.w3.org/TR/1999/REC-xpath-19991116'] ) ) &&
                    ( !empty( $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query'] ) )
                ) {
                    $transNode->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
                    $XPathNode = $this->createNewSignNode('XPath', $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['query']);
                    $transNode->appendChild($XPathNode);
                    if (!empty( $transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'] )) {
                        foreach ($transform['http://www.w3.org/TR/1999/REC-xpath-19991116']['namespaces'] AS $prefix => $namespace) {
                            $XPathNode->setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:$prefix", $namespace);
                        }
                    }
                }
                else {
                    $transNode->setAttribute('Algorithm', $transform);
                }
            }
        }
        elseif (!empty( $this->canonicalMethod )) {
            $transNode = $this->createNewSignNode('Transform');
            $transNodes->appendChild($transNode);
            $transNode->setAttribute('Algorithm', $this->canonicalMethod);
        }

        $canonicalData = $this->processTransforms($refNode, $node);
        $digValue      = $this->calculateDigest($algorithm, $canonicalData);

        $digestMethod = $this->createNewSignNode('DigestMethod');
        $refNode->appendChild($digestMethod);
        $digestMethod->setAttribute('Algorithm', $algorithm);

        $digestValue = $this->createNewSignNode('DigestValue', $digValue);
        $refNode->appendChild($digestValue);
    }

    /**
     * @param DOMDocument $node
     * @param $algorithm
     * @param null $arTransforms
     * @param null $options
     */
    public function addReference(DOMDocument $node, $algorithm, $arTransforms = null, $options = null)
    {
        if ($xpath = $this->getXPathObj()) {
            $query   = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            /** @var DOMElement $sInfo */
            if ($sInfo = $nodeset->item(0)) {
                $this->addRefInternal($sInfo, $node, $algorithm, $arTransforms, $options);
            }
        }
    }

    /**
     * @param $arNodes
     * @param $algorithm
     * @param null $arTransforms
     * @param null $options
     */
    public function addReferenceList($arNodes, $algorithm, $arTransforms = null, $options = null)
    {
        if ($xpath = $this->getXPathObj()) {
            $query   = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            /** @var DOMElement $sInfo */
            if ($sInfo = $nodeset->item(0)) {
                foreach ($arNodes AS $node) {
                    $this->addRefInternal($sInfo, $node, $algorithm, $arTransforms, $options);
                }
            }
        }
    }

    /**
     * @param $data
     * @param null $mimetype
     * @param null $encoding
     *
     * @return DOMElement
     */
    public function addObject($data, $mimetype = null, $encoding = null)
    {
        $objNode = $this->createNewSignNode('Object');
        $this->sigNode->appendChild($objNode);
        if (!empty( $mimetype )) {
            $objNode->setAttribute('MimeType', $mimetype);
        }
        if (!empty( $encoding )) {
            $objNode->setAttribute('Encoding', $encoding);
        }

        if ($data instanceof DOMElement) {
            $newData = $this->sigNode->ownerDocument->importNode($data, true);
        }
        else {
            $newData = $this->sigNode->ownerDocument->createTextNode($data);
        }
        $objNode->appendChild($newData);

        return $objNode;
    }

    /**
     * @param null $node
     *
     * @return null|XMLSecurityKey
     */
    public function locateKey($node = null)
    {
        if (empty( $node )) {
            $node = $this->sigNode;
        }
        if (!$node instanceof DOMNode) {
            return null;
        }
        if ($doc = $node->ownerDocument) {
            $xpath = new DOMXPath($doc);
            $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
            $query     = "string(./secdsig:SignedInfo/secdsig:SignatureMethod/@Algorithm)";
            $algorithm = $xpath->evaluate($query, $node);
            if ($algorithm) {
                try {
                    $objKey = new XMLSecurityKey($algorithm, array('type' => 'public'));
                } catch (Exception $e) {
                    return null;
                }

                return $objKey;
            }
        }

        return null;
    }

    /**
     * @param XMLSecurityKey $objKey
     *
     * @return int
     * @throws Exception
     */
    public function verify(XMLSecurityKey $objKey)
    {
        $doc   = $this->sigNode->ownerDocument;
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
        $query    = "string(./secdsig:SignatureValue)";
        $sigValue = $xpath->evaluate($query, $this->sigNode);
        if (empty( $sigValue )) {
            throw new Exception("Unable to locate SignatureValue");
        }

        return $objKey->verifySignature($this->signedInfo, base64_decode($sigValue));
    }

    /**
     * @param XMLSecurityKey $objKey
     * @param $data
     *
     * @return mixed
     * @throws Exception
     */
    public function signData(XMLSecurityKey $objKey, $data)
    {
        return $objKey->signData($data);
    }

    /**
     * @param XMLSecurityKey $objKey
     * @param DOMElement $appendToNode
     */
    public function sign(XMLSecurityKey $objKey, DOMElement $appendToNode = null)
    {
        // If we have a parent node append it now so C14N properly works
        if ($appendToNode != null) {
            $this->resetXPathObj();
            $this->appendSignature($appendToNode);
            $this->sigNode = $appendToNode->lastChild;
        }
        if ($xpath = $this->getXPathObj()) {
            $query   = "./secdsig:SignedInfo";
            $nodeset = $xpath->query($query, $this->sigNode);
            if ($sInfo = $nodeset->item(0)) {
                $query   = "./secdsig:SignatureMethod";
                $nodeset = $xpath->query($query, $sInfo);
                /** @var DOMElement $sMethod */
                $sMethod = $nodeset->item(0);
                $sMethod->setAttribute('Algorithm', $objKey->type);
                $data         = $this->canonicalizeData($sInfo, $this->canonicalMethod);
                $sigValue     = base64_encode($this->signData($objKey, $data));
                $sigValueNode = $this->createNewSignNode('SignatureValue', $sigValue);
                if ($infoSibling = $sInfo->nextSibling) {
                    $infoSibling->parentNode->insertBefore($sigValueNode, $infoSibling);
                }
                else {
                    $this->sigNode->appendChild($sigValueNode);
                }
            }
        }
    }

    /**
     * @param XMLSecurityKey $objKey
     * @param null $parent
     */
    public function appendKey(XMLSecurityKey $objKey, $parent = null)
    {
        $objKey->serializeKey($parent);
    }


    /**
     * This function inserts the signature element.
     *
     * The signature element will be appended to the element, unless $beforeNode is specified. If $beforeNode
     * is specified, the signature element will be inserted as the last element before $beforeNode.
     *
     * @param DOMElement $node The node the signature element should be inserted into.
     * @param DOMElement $beforeNode The node the signature element should be located before.
     *
     * @return DOMNode The signature element node
     */
    public function insertSignature(DOMElement $node, DOMElement $beforeNode = null)
    {
        $document         = $node->ownerDocument;
        $signatureElement = $document->importNode($this->sigNode, true);

        if ($beforeNode == null) {
            return $node->insertBefore($signatureElement);
        }
        else {
            return $node->insertBefore($signatureElement, $beforeNode);
        }
    }

    /**
     * @param DOMElement $parentNode
     * @param bool $insertBefore
     *
     * @return DOMNode
     */
    public function appendSignature(DOMElement $parentNode, $insertBefore = false)
    {
        $beforeNode = $insertBefore ? $parentNode->firstChild : null;

        return $this->insertSignature($parentNode, $beforeNode);
    }

    /**
     * @param $cert
     * @param bool $isPEMFormat
     *
     * @return string
     */
    static function get509XCert($cert, $isPEMFormat = true)
    {
        $certs = XMLSecurityDSig::staticGet509XCerts($cert, $isPEMFormat);
        if (!empty( $certs )) {
            return $certs[0];
        }

        return '';
    }

    /**
     * @param $certs
     * @param bool $isPEMFormat
     *
     * @return array
     */
    static function staticGet509XCerts($certs, $isPEMFormat = true)
    {
        if ($isPEMFormat) {
            $data     = '';
            $certlist = array();
            $arCert   = explode("\n", $certs);
            $inData   = false;
            foreach ($arCert AS $curData) {
                if (!$inData) {
                    if (strncmp($curData, '-----BEGIN CERTIFICATE', 22) == 0) {
                        $inData = true;
                    }
                }
                else {
                    if (strncmp($curData, '-----END CERTIFICATE', 20) == 0) {
                        $inData     = false;
                        $certlist[] = $data;
                        $data       = '';
                        continue;
                    }
                    $data .= trim($curData);
                }
            }

            return $certlist;
        }
        else {
            return array($certs);
        }
    }

    /**
     * @param $parentRef
     * @param $cert
     * @param bool $isPEMFormat
     * @param bool $isURL
     * @param null $xpath
     * @param null $options
     *
     * @throws Exception
     */
    static function staticAdd509Cert($parentRef, $cert, $isPEMFormat = true, $isURL = false, $xpath = null, $options = null)
    {
        if ($isURL) {
            $cert = file_get_contents($cert);
        }
        if (!$parentRef instanceof DOMElement) {
            throw new Exception('Invalid parent Node parameter');
        }
        $baseDoc = $parentRef->ownerDocument;

        if (empty( $xpath )) {
            $xpath = new DOMXPath($parentRef->ownerDocument);
            $xpath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS);
        }

        $query   = "./secdsig:KeyInfo";
        $nodeset = $xpath->query($query, $parentRef);
        $keyInfo = $nodeset->item(0);
        if (!$keyInfo) {
            $inserted = false;
            $keyInfo  = $baseDoc->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:KeyInfo');

            $query   = "./secdsig:Object";
            $nodeset = $xpath->query($query, $parentRef);
            if ($sObject = $nodeset->item(0)) {
                $sObject->parentNode->insertBefore($keyInfo, $sObject);
                $inserted = true;
            }

            if (!$inserted) {
                $parentRef->appendChild($keyInfo);
            }
        }

        // Add all certs if there are more than one
        $certs = XMLSecurityDSig::staticGet509XCerts($cert, $isPEMFormat);

        // Attach X509 data node
        $x509DataNode = $baseDoc->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:X509Data');
        $keyInfo->appendChild($x509DataNode);

        $issuerSerial = false;
        if (is_array($options)) {
            if (!empty( $options['issuerSerial'] )) {
                $issuerSerial = true;
            }
        }

        // Attach all certificate nodes and any additional data
        foreach ($certs as $X509Cert) {
            if ($issuerSerial) {
                if ($certData = openssl_x509_parse("-----BEGIN CERTIFICATE-----\n" . chunk_split($X509Cert, 64, "\n") . "-----END CERTIFICATE-----\n")) {
                    if ($issuerSerial && !empty( $certData['issuer'] ) && !empty( $certData['serialNumber'] )) {
                        if (is_array($certData['issuer'])) {
                            $parts = array();
                            foreach ($certData['issuer'] AS $key => $value) {
                                array_unshift($parts, "$key=$value");
                            }
                            $issuerName = implode(',', $parts);
                        }
                        else {
                            $issuerName = $certData['issuer'];
                        }

                        $x509IssuerNode = $baseDoc->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:X509IssuerSerial');
                        $x509DataNode->appendChild($x509IssuerNode);

                        $x509Node = $baseDoc->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:X509IssuerName', $issuerName);
                        $x509IssuerNode->appendChild($x509Node);
                        $x509Node = $baseDoc->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:X509SerialNumber', $certData['serialNumber']);
                        $x509IssuerNode->appendChild($x509Node);
                    }
                }

            }
            $x509CertNode = $baseDoc->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:X509Certificate', $X509Cert);
            $x509DataNode->appendChild($x509CertNode);
        }
    }

    /**
     * @param $cert
     * @param bool $isPEMFormat
     * @param bool $isURL
     * @param null $options
     *
     * @throws Exception
     */
    public function add509Cert($cert, $isPEMFormat = true, $isURL = false, $options = null)
    {
        if ($xpath = $this->getXPathObj()) {
            self::staticAdd509Cert($this->sigNode, $cert, $isPEMFormat, $isURL, $xpath, $options);
        }
    }

    /* This function retrieves an associative array of the validated nodes.
     *
     * The array will contain the id of the referenced node as the key and the node itself
     * as the value.
     *
     * Returns:
     *  An associative array of validated nodes or NULL if no nodes have been validated.
     */
    /**
     * @return null
     */
    public function getValidatedNodes()
    {
        return $this->validatedNodes;
    }

}