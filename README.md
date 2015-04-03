[![Build Status](https://travis-ci.org/ddvzwzjm/xmlseclibs.svg?branch=master)](https://travis-ci.org/ddvzwzjm/xmlseclibs)
[![Coverage Status](https://coveralls.io/repos/ddvzwzjm/xmlseclibs/badge.svg)](https://coveralls.io/r/ddvzwzjm/xmlseclibs)

# XMLSecLibs 

Based on [robrichards/xmlseclibs](https://github.com/robrichards/xmlseclibs)

Quote from source repo:
```
xmlseclibs is a library written in PHP for working with XML Encryption and Signatures.
xmlseclibs requires PHP version 5 or greater.
The author of xmlseclibs is Rob Richards.
xmlseclibs is being used in many different software, one of them is simpleSAMLphp. 
Mailing List: https://groups.google.com/forum/#!forum/xmlseclibs
```
## What's new?

1. Only PHP 5.3+, no 5.0 legacy
2. PSR-0 compatible
3. *Stable* Composer package available `composer require ddvzwzjm/xmlseclibs`
4. PHPUnit instead of ancient .phpt
5. Travis CI and better Code Coverage (67% vs 53%)
6. Examples (tbd)
7. Docs (tbd)

## PHPUnit Tests

To run tests
```
composer install --dev
vendor/bin/phpunit -c phpunit.xml.dist
```
