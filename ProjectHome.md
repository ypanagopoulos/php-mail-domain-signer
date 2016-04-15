**PHP class for Add DKIM-Signature and DomainKey-Signature on your mail**

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