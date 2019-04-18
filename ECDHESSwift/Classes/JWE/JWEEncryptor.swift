//
//  JWEEncryptor.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/17.
//

import Foundation
import JOSESwift

public protocol JWEEncryptor {
    func encrypt(
        plaintext: Data,
        key: JWK,
        header: JSONWebEncryptionHeader,
        options: [String: Any]
    ) throws -> (header: JSONWebEncryptionHeader, encryptedKey: Data, iv: Data, ciphertext: Data, tag: Data)

    func decrypt(
        key: JWK,
        header: JSONWebEncryptionHeader,
        encryptedKey: Data,
        iv: Data,
        ciphertext: Data,
        tag: Data, aad: Data
    ) throws -> Data
}
