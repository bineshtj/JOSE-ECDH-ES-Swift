# ECDHESSwift

[![CI Status](https://travis-ci.com/104corp/JOSE-ECDH-ES-Swift.svg?branch=master&style=flat)](https://travis-ci.com/104corp/JOSE-ECDH-ES-Swift)
[![codecov](https://codecov.io/gh/104corp/JOSE-ECDH-ES-Swift/branch/master/graph/badge.svg)](https://codecov.io/gh/104corp/JOSE-ECDH-ES-Swift)
[![Version](https://img.shields.io/cocoapods/v/ECDHESSwift.svg?style=flat)](https://cocoapods.org/pods/ECDHESSwift)
[![License](https://img.shields.io/cocoapods/l/ECDHESSwift.svg?style=flat)](https://cocoapods.org/pods/ECDHESSwift)
[![Platform](https://img.shields.io/cocoapods/p/ECDHESSwift.svg?style=flat)](https://cocoapods.org/pods/ECDHESSwift)

## Features

- **JWE**: Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static (ECDH-ES) arbitrary data encryption and decryption.

### Elliptic Curve

- [x] P-256
- [x] P-384
- [x] P-521

### Key Management Algorithms

- [x] ECDH-ES: Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF.
- [x] ECDH-ES+A128KW: ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
- [x] ECDH-ES+A192KW: ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
- [x] ECDH-ES+A256KW: ECDH-ES using Concat KDF and CEK wrapped with "A256KW".

### Encryption Algorithms

- [x] A128GCM: AES GCM using 128-bit key.
- [x] A192GCM: AES GCM using 192-bit key.
- [x] A256GCM: AES GCM using 256-bit key.

### Compression Algorithms

- [x] DEF: Compression with the DEFLATE [RFC1951] algorithm.

### JWE Serializations

- Compact Serialization

## Requirements

- iOS >= 10.0 
- JOSESwift 1.8

## Installation

ECDHESSwift is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'ECDHESSwift'
```

## Usage

Encryption
```swift
let pubJwk = """
  {
    "crv": "P-256",
    "kty": "EC",
    "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
    "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
  }
"""

let plaintext = """
每覽昔人興感之由，若合一契，未嘗不臨文嗟悼，不能喻之於懷，固知一死生為虛誕，彭殤為妄作。後之視今，亦猶今之視昔，悲夫！故列時人，錄其所述，雖世殊事異，所以興懷，其致一也。後之覽者，亦將有感於斯文。
""".data(using: .utf8)!

let encryptionJwe = try EcdhEsJwe(plaintext: plaintext, pubKeyJwkJson: pubJwk, headerDic: ["alg": "ECDH-ES+A256KW", "enc": "A256GCM"])

let jweCompactString = encryptionJwe.compactSerializedString

```


Decryption
```swift
let privJwk = """
  {
    "crv": "P-256",
    "d": "920OCD0fW97YXbQNN-JaOtaDgbuNyVxXgKwjfXPPqv4",
    "kty": "EC",
    "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
    "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
  }
"""

let jweCompactString = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsieSI6IkgwX1JwdTBqaHpjcVdiaFRiNjg0OVcyZV9xQkxIVFNXSnVYQVYyRjRmeGsiLCJraWQiOiIxQUJBM0UxOS00RTlFLTRFNTAtOTAxOC01NDY5OTExMEY2NTciLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkIxUGxLWW10ekdUemFUT2FPd1F1aEVKOXFFNDIyVVpEaHlWNHZkSGpZdlkifX0.eD9Mxp9SBS6QMRh-rP-shwmM0fCj34ZHDUBjdADgndl_J4qIk60OWA.P_pq05ZWReabvX1a.a9YuXgj1EI-DOgWq8da8H8c1P7Qn4LMiJt81My3uC9SmV9NHY6vKtqFVlB1TLHdJ7niT68Gd_T5ow_K_BUOm57armWx9UAaTBLV8gWETRhtmF7vCEPZEVIrK07aTHRvhkF57BBlgeMbpIfuXAL8Ks_S5Y_0WkzjBfpMCx0y7I4UPUYc6aaJLxkDlz0L54HiPpJD7jx1ExPZ_b6QHVbLHnQrywOPBZXbRIax-g8GuTW1MYhazIoKyStSmImHJxMBiA5OkfxuGaiLiz8_UpUyDqEbFDYJl_gDm-ePZbNhcM46XFL0SQidNOmcrmzXMjOMNDTpG3zVCg05EkM7Ztm-bIuOSRAWwYDLc92cDlSCzfH_77p3UWhMiRZicrrLULUXnkKi-gOeg.TOEKC6oNaaND_Etb5qxt5A"

let decryptionJwe = try EcdhEsJwe(compactSerializedString: jweCompactString)

let plaintext = try! decryptionJwe.decrypt(privKeyJwkJson: privJwk)

```
