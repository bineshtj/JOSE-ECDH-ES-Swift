//
//  ECDH.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation
import JOSESwift

/**
 Derive ECDH Key Data

 - Parameter ecPrivJwk: EC private JWK
 - Parameter ecPubJwk: EC public JWK
 - Parameter bitLen: key size

 - Throws: ECDHError.deriveKeyFail

 - Returns: Result of key exchange operation as a Data
 **/
func ecdhDeriveBits(ecPrivJwk: ECPrivateKey, ecPubJwk: ECPublicKey, bitLen: Int = 0) throws -> Data {
    if ecPrivJwk.crv != ecPubJwk.crv {
        throw ECDHEESError.deriveKeyFail(reason: "Private Key curve and Public Key curve are different")
    }
    let pubKey = try ecPubJwk.converted(to: SecKey.self)
    let eprivKey = try ecPrivJwk.converted(to: SecKey.self)
    let parameters = [String: Any]()
    var error: Unmanaged<CFError>?

    if let derivedData = SecKeyCopyKeyExchangeResult(eprivKey, SecKeyAlgorithm.ecdhKeyExchangeStandard, pubKey, parameters as CFDictionary, &error) {
        if bitLen > 0 {
            return truncateBitLen(from: (derivedData as Data), bitLen: bitLen)
        }
        return (derivedData as Data)
    }
    if let errStr = error?.takeRetainedValue().localizedDescription {
        throw ECDHEESError.deriveKeyFail(reason: errStr)
    }
    throw ECDHEESError.deriveKeyFail(reason: "Derive Key Fail")
}
