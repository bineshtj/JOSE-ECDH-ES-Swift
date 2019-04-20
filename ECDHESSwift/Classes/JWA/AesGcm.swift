//
//  AesGcm.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import CryptoSwift
import Foundation

func aesGcmEncrypt(plaintext: Data, key: Data, iv: Data, tagLen: Int, aad: Data) throws -> (ciphertext: Data, tag: Data) {
    let gcm = GCM(
        iv: [UInt8](iv),
        additionalAuthenticatedData: [UInt8](aad),
        tagLength: tagLen,
        mode: .detached)

    let aes = try AES(key: [UInt8](key), blockMode: gcm, padding: .noPadding)
    let ciphertext = try aes.encrypt([UInt8](plaintext))
    let tag = gcm.authenticationTag!

    return (Data(ciphertext), Data(tag))
}

func aesGcmDecrypt(ciphertext: Data, key: Data, iv: Data, tag: Data, aad: Data) throws -> Data {
    let gcm = GCM(
        iv: [UInt8](iv),
        authenticationTag: [UInt8](tag),
        additionalAuthenticatedData: [UInt8](aad),
        mode: .detached)

    let aes = try AES(key: [UInt8](key), blockMode: gcm, padding: .noPadding)
    return Data(try aes.decrypt([UInt8](ciphertext)))
}
