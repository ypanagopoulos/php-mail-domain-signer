# Introduction #
PHP Mail Domain Signer is PHP Class to create DKIM-Signature and DomainKey-Signature for your email data before you sending it on SMTP.

It refer to [RFC4871](http://tools.ietf.org/html/rfc4871) About DomainKeys Identified Mail (DKIM) Signatures and [RFC4870](http://tools.ietf.org/html/rfc4870) About Domain-Based Email Authentication Using Public Keys Advertised in the DNS (DomainKeys)

# Features #
PHP Mail Domain Signer had several great features and Easy to integrated into your current mailer script.

  * Object Oriented
  * Signing from Raw Email Data
  * Signing from Custom Array of Headers and Body
  * Use easy to verifier canonicalization alghoritm "relaxed/relaxed" and "nofws"
  * Able to return whole signed mail data, or only signed headers in String or Array
  * You can easly choose only DKIM, DomainKey or both signature
  * Simple and Fast Implementation of alghoritm

# How To Use #
PHP Mail Domain Signer was PHP Source code, it only one file **class.mailDomainSigner.php**
to included into your php script then you can easly create new mailDomainSigner object.

## Creating Keys ##
You need to create public and private key to sign your email with PHP Mail Domain Signer.
I reccomended use [openssl](http://www.openssl.org/)
because it open source and default in some OS like LINUX.

Here how you should create your keys:
```
openssl genrsa -out key.priv 384
openssl rsa -in key.priv -out key.pub -pubout -outform PEM
```

The first command used to create private key and save it into key.priv, you can change the key bit-length with other values like 1024.

**NOTE:** According to [RFC4870](http://tools.ietf.org/html/rfc4870) max length should be 2048bit, ( the practical constraint that a 2048-bit key is the largest key that fits within a 512-byte DNS UDP response packet )

The second command used to create public key and save it into key.pub.

### The Private Key ###
Contents of Private key **key.priv** will be used in mailDomainSigner constructor, you can create new mailDomainSigner with something like
```
$mds = &new mailDomainSigner(
  file_get_contents("key.priv"),
  "yourdomain.com",
  "yourselector"
);
```

### The Public Key ###
Contents of Public key **key.pub** will be used in DNS TXT record, Please read [RFC4870-Page12](http://tools.ietf.org/html/rfc4870#page-13) to know detail about DNS TXT for storing public key.
**NOTE:**
  * Don't use g tag (_granularity of the key_) if you want to create DomainKey-Signature
  * Remove `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----` and all spaces/line characters from public key before add it into TXT record

### Setting Your DNS TXT Record ###
```
yourselector._domainkey.yourdomain.com. IN TXT "v=DKIM1;k=rsa;h=sha1;s=email;t=s;p=YOUR_PUBLIC_KEY_DATA_WITHOUT"
```

If you want to test your dns configuration, you can use php script:
```
print_r(dns_get_record("yourselector._domainkey.yourdomain.com",DNS_TXT));
```
or Linux shell command:
```
host -t txt yourselector._domainkey.yourdomain.com
```