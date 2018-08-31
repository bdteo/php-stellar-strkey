# Stellar StrKey in PHP
This repo is a 1:1 PHP implementation of the StrKey helper from the Stellar Js SDK

See it at: https://github.com/stellar/js-stellar-base/blob/master/src/strkey.js

----
```bash
composer require bdteo/php-stellar-strkey
```

According to the Stellar implementation: the 56 character base32 encoded string key can contain binary data of public key, private key, preAuthTx or a sha256Hash.
( Stellar uses Ed25519 public/private keys - https://ed25519.cr.yp.to/ )

----

You can use this class to validate Stellar addresses.
 
You can use this class also to check the validity of a Stellar string key, extract the payload data or encode payload data into a sting key. 

Here is an example:

```php
use Bdteo\Stellar\StrKey;

$testAddress = 'GDDJ7IIWHZV4KWEX3QH437C3QZL4RTJCSXNVRAQMFESQP6WNZAM4N32Y';
$strKey = new StrKey();

$isValid = $strKey->isValidStellarAddress($testAddress);

echo $isValid
    ? 'Awesome ! The address is valid !'
    : 'Too bad ! Your address is incorrect !'; 
```
---
Used on https://tokenrush.io/
---
I am planning to publish more general purpose crypto tools in the near future ! 

