//
//  KeyWrap.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import CommonCrypto
import Foundation

func keyWrap(kek: Data, key: Data) throws -> Data {
    var wrappedKeyLen = CCSymmetricWrappedSize(CCWrappingAlgorithm(kCCWRAPAES), key.count)
    var wrappedKey = [UInt8](repeating: 0, count: wrappedKeyLen)
    guard kCCSuccess == CCSymmetricKeyWrap(
        CCWrappingAlgorithm(kCCWRAPAES),
        CCrfc3394_iv, CCrfc3394_ivLen,
        Array(kek), kek.count,
        Array(key), key.count,
        &wrappedKey, &wrappedKeyLen
    ) else {
        throw ECDHEESError.wrapKeyFail
    }
    return Data(wrappedKey)
}

func keyUnwrap(kek: Data, encryptedKey: Data) throws -> Data {
    var rawKeyLen = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), encryptedKey.count)
    var rawKey = [UInt8](repeating: 0, count: rawKeyLen)
    guard kCCSuccess == CCSymmetricKeyUnwrap(
        CCWrappingAlgorithm(kCCWRAPAES),
        CCrfc3394_iv, CCrfc3394_ivLen,
        Array(kek), kek.count,
        Array(encryptedKey), encryptedKey.count,
        &rawKey, &rawKeyLen
    ) else {
        throw ECDHEESError.unwrapKeyFail
    }
    return Data(rawKey)
}
