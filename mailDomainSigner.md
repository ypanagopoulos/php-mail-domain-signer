# Class: mailDomainSigner #

Source Location: **/lib/class.mailDomainSigner.php**

### Class Overview ###
mailDomainSigner - PHP class for Add DKIM-Signature and DomainKey-Signature on your mail

  * Author(s): **Ahmad Amarullah**

### Class Details ###
mailDomainSigner - PHP class for Add DKIM-Signature and DomainKey-Signature on your mail

```
Requirement: >= PHP 5.3.0 For lower version, find "#^--for ver < PHP5.3" comment
```

  * author: **Ahmad Amarullah**
  * link: http://code.google.com/p/php-mail-domain-signer/

# Class Methods #

## constructor `__`construct ##
```
mailDomainSigner __construct(string $private_key, string $d, string $s)
```

Constructor

### Tags ###
  * author: **Ahmad Amarullah**
  * access: **public**

### Parameters ###
  * _string_ **$private`_`key** Raw Private Key to Sign the mail
  * _string_ **$d** The domain name of the signing domain
  * _string_ **$s** The selector used to form the query for the public key

### Example ###
```
// Include PHP Mail Domain Signer Class File
include_once './lib/class.mailDomainSigner.php';

$domain_d         = 'example.com';
$domain_s					= 'burger';
$domain_priv = '-----BEGIN RSA PRIVATE KEY-----
MIHzAgEAAjEA6TdJJo8KKw1Vvc59PFSn4WvayJTgrDIt35TZVp3FdUiQ4btyABb8
X2LzfGByda1BAgMBAAECMQCZZd78uMtEZCIIleB0JW7DbDDdDGf3e4zFLzV+qoo7
KnD8H2HQDu4bBvIaHAiroQ0CGQD/AX+WgauA2EnyxuX0UM5LH8yJUri6ir8CGQDq
IAphW4DwlJLWswsgN3pNgVdwTNr1x/8CGCZPnVGJTbDfzcxRoX6hHT0gG+SNrv8n
lQIYDwlJwWDwEgNovtM25rXJbArfg73b3icfAhkAjJouzz3NXqSNc7lXx17vAN3w
ExoyBmSJ
-----END RSA PRIVATE KEY-----';

// Create mailDomainSigner Object
$mds = &new mailDomainSigner($domain_priv,$domain_d,$domain_s);

```


## method bodyRelaxCanon ##
```
string bodyRelaxCanon(string $body)
```

The "relaxed" Body Canonicalization Algorithm Function implementation according to RFC4871

### Tags ###
  * author: **Ahmad Amarullah**
  * link: http://tools.ietf.org/html/rfc4871#page-15
  * access: **public**
  * return: **Relaxed Body Canonicalizated data**

### Parameters ###
  * _string_ **$body** Body String to Canonicalization

## method getDKIM ##
```
string getDKIM(string $h, array $_h, string $body)
```

DKIM-Signature Header Creator Function implementation according to RFC4871

Originally code inspired by AddDKIM function in PHP-DKIM by Eric Vyncke And rewrite it for better result

The function use relaxed/relaxed canonicalization alghoritm for better verifing validation

different from original PHP-DKIM that used relaxed/simple canonicalization alghoritm

Doesn't include z, i and q tag for smaller data because it doesn't really needed

### Tags ###
  * author: **Ahmad Amarullah**
  * link: http://php-dkim.sourceforge.net/
  * link: http://tools.ietf.org/html/rfc4871#page-15
  * access: **public**
  * return: **DKIM-Signature Header String**

### Parameters ###
  * _string_ **$h** Signed header fields, A colon-separated list of header field names that identify the header fields presented to the signing algorithm
  * _array_ **$`_`h** 	Array of headers in same order with $h (Signed header fields)
  * _string_ **$body** 	Raw Email Body String

## method getDomainKey ##
```
string getDomainKey(string $h, array $_h, string $body)
```

DomainKey-Signature Header Creator Function implementation according to RFC4870

The function use nofws canonicalization alghoritm for better verifing validation

**NOTE:** the $h and $`_`h arguments must be in right order if to header location upper the from header it should ordered like "to:from", don't randomize the order for better validating result.

**NOTE:** if your DNS TXT contained g=**, remove it**

### Tags ###
  * author: **Ahmad Amarullah**
  * link: http://tools.ietf.org/html/rfc4870
  * access: **public**
  * return: **DomainKey-Signature Header String**

### Parameters ###
  * _string_ **$h** Signed header fields, A colon-separated list of header field names that identify the header fields presented to the signing algorithm
  * _array_ **$`_`h** 	Array of headers in same order with $h (Signed header fields)
  * _string_ **$body** 	Raw Email Body String

## method headRelaxCanon ##
```
string headRelaxCanon(string $s)
```

The "relaxed" Header Canonicalization Algorithm Function implementation according to RFC4871

Originally taken from RelaxedHeaderCanonicalization function in [PHP-DKIM](http://php-dkim.sourceforge.net/) by Eric Vyncke

### Tags ###
  * author: **Eric Vyncke**
  * link: http://php-dkim.sourceforge.net/
  * link: http://tools.ietf.org/html/rfc4871#page-14
  * access: **public**
  * return: **Relaxed Header Canonicalizated data**

### Parameters ###
  * _string_ **$s** Header String to Canonicalization

## method nofws ##
```
string nofws(array $raw_headers, string $raw_body)
```

The nofws ("No Folding Whitespace") Canonicalization Algorithm Function implementation according to RFC4870

### Tags ###
  * author: **Ahmad Amarullah**
  * link: http://tools.ietf.org/html/rfc4870#page-19
  * access: **public**
  * return: **nofws Canonicalizated data**

### Parameters ###
  * _array_ **$raw`_`headers** Array of Mail Headers
  * _string_ **$raw`_`body** 	Raw Mail body

## method sign ##
```
mixed sign( string $mail_data, [string $suggested_h = "from:to:subject"], [bool $create_dkim = true], [bool $create_domainkey = true], [integer $out_sign_header_only = false])
```

Auto Sign RAW Mail Data with DKIM-Signature and DomailKey-Signature

It Support auto positioning Signed header fields

### Tags ###
  * author: **Ahmad Amarullah**
  * access: **public**
  * return: **Signature Headers with/without original data as String/Array depended on $out\_sign\_header\_only parameter**

### Parameters ###
  * _string_ **$mail\_data** Raw Mail Data to be signed
  * _string_ **$suggested\_h** Suggested Signed Header Fields, separated by colon ":" Default: string("from:to:subject")
  * _bool_ **$create\_dkim** If true, it will generate DKIM-Signature for $mail\_data Default: boolean(true)
  * _bool_ **$create\_domainkey** If true, it will generate DomailKey-Signature for $mail\_data Default: boolean(true)
  * _integer_ **$out\_sign\_header\_only** If true or 1, it will only return signature headers as String If 2, it will only return signature headers as Array If false or 0, it will return signature headers with original mail data as String Default: boolean(false)