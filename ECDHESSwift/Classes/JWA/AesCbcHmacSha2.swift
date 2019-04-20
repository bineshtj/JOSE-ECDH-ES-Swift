//
//  AesCbcHmacSha2.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/20.
//

import CryptoSwift
import Foundation

func aesCbcHmacSha2Encrypt(hash: Hash, macKey: Data, plaintext: Data, key: Data, iv: Data, tagLen: Int, aad: Data) throws -> (ciphertext: Data, tag: Data) {
    let ciphertext = Data(try AES(key: [UInt8](key), blockMode: CBC(iv: [UInt8](iv)), padding: .pkcs7).encrypt([UInt8](plaintext)))
    let tag = computeTag(hash, macKey, aad, iv, ciphertext, tagLen)
    return (ciphertext, tag)
}

func aesCbcHmacSha2Decrypt(hash: Hash, macKey: Data, ciphertext: Data, key: Data, iv: Data, tag: Data, aad: Data, authTagLen: Int) throws -> Data {
    let plaintext = try AES(key: [UInt8](key), blockMode: CBC(iv: [UInt8](iv)), padding: .pkcs7).decrypt([UInt8](ciphertext))
    let computedtag = computeTag(hash, macKey, aad, iv, ciphertext, authTagLen)
    guard tag == computedtag else {
        throw ECDHEESError.decryptFail(reason: "Authentication tag validation fail")
    }
    return Data(plaintext)
}

fileprivate func computeTag(_ hash: Hash, _ macKey: Data, _ aad: Data, _ iv: Data, _ ciphertext: Data, _ tagLen: Int) -> Data {
    // A || IV || E || AL.
    let macSource = aad + iv + ciphertext + intToData(value: UInt64(aad.count * 8).bigEndian)
    return (hash.mac(key: macKey, value: macSource)).subdata(in: 0 ..< tagLen)
}
