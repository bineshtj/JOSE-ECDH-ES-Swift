//
//  Algorithm.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation

protocol KeySizeKnowable {
    var keySize: Int {get}
}

extension KeySizeKnowable {
    func guardKeySize(key: Data) throws {
        guard key.count * 8 == self.keySize else {
            throw ECDHEESError.invalidEncryptionKeySize
        }
    }
}

enum KeyWrapAlgorithm: String, KeySizeKnowable, CaseIterable {
    case A128KW = "A128KW"
    case A192KW = "A192KW"
    case A256KW = "A256KW"
    
    var keySize: Int {
        switch self {
        case .A128KW:
            return 128
        case .A192KW:
            return 192
        case .A256KW:
            return 256
        }
    }
    func wrap(kek: Data, rawKey: Data) throws -> Data {
        try guardKeySize(key: kek)
        return try keyWrap(kek: kek, key: rawKey)
    }
    
    func unwrap(kek: Data, wrappedKey: Data) throws -> Data {
        try guardKeySize(key: kek)
        return try keyUnwrap(kek: kek, encryptedKey: wrappedKey)
    }
}

enum EncryptionAlgorithm: String, KeySizeKnowable, CaseIterable {
    case A128GCM = "A128GCM"
    case A192GCM = "A192GCM"
    case A256GCM = "A256GCM"
    var keySize: Int {
        switch self {
        case .A128GCM:
            return 128
        case .A192GCM:
            return 192
        case .A256GCM:
            return 256
        }
    }
    
    func encrypt(
        plaintext: Data,
        key: Data,
        iv: Data,
        tagLen: Int = 16,
        aad: Data? = nil
        ) throws -> (ciphertext: Data, tag: Data) {
        try guardKeySize(key: key)
        return try aesGcmEncrypt(plaintext: plaintext, key: key, iv: iv, tagLen: tagLen, aad: aad)
    }
    
    func decrypt(
        ciphertext: Data,
        key: Data,
        iv: Data,
        tag: Data,
        aad: Data? = nil
        ) throws -> Data {
        try guardKeySize(key: key)
        return try aesGcmDecrypt(ciphertext: ciphertext, key: key, iv: iv, tag: tag, aad: aad)
    }
    
    var ivSize: Int {
        switch self {
        case .A128GCM, .A192GCM, .A256GCM:
            return 96
        }
    }
    
    var tagLength: Int {
        switch self {
        case .A128GCM, .A192GCM, .A256GCM:
            return 128
        }
    }
}

enum EcdhEsAlgorithm: String, CaseIterable {
    case ECDH_ES = "ECDH-ES"
    case ECDH_ES_A128KW = "ECDH-ES+A128KW"
    case ECDH_ES_A192KW = "ECDH-ES+A192KW"
    case ECDH_ES_A256KW = "ECDH-ES+A256KW"
    
    var keyWrapAlgorithm: KeyWrapAlgorithm? {
        switch self {
        case .ECDH_ES:
            return nil
        case .ECDH_ES_A128KW:
            return .A128KW
        case .ECDH_ES_A192KW:
            return .A192KW
        case .ECDH_ES_A256KW:
            return .A256KW
        }
    }
}
