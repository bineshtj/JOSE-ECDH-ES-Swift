//
//  Algorithm.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation
import JOSESwift

enum JSONWebEncryptionCompressionAlgorithm: String {
    case DEFLATE = "DEF"

    var compress: (_ data: Data) throws -> Data {
        switch self {
        case .DEFLATE:
            return deflateCompress
        }
    }

    var decompress: (_ data: Data) throws -> Data {
        switch self {
        case .DEFLATE:
            return deflateDecompress
        }
    }
}

protocol KeySizeKnowable {
    var keyBitSize: Int { get }
}

extension KeySizeKnowable {
    func guardKeySize(key: Data) throws {
        guard key.count * 8 == keyBitSize else {
            throw ECDHEESError.invalidKeySize
        }
    }
}

enum KeyWrapAlgorithm: String, KeySizeKnowable, CaseIterable {
    case A128KW
    case A192KW
    case A256KW

    var keyBitSize: Int {
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
    case A128GCM
    case A192GCM
    case A256GCM
    case A128CBC_HS256 = "A128CBC-HS256"
    case A192CBC_HS384 = "A192CBC-HS384"
    case A256CBC_HS512 = "A256CBC-HS512"

    var keyBitSize: Int {
        switch self {
        case .A128GCM:
            return 128
        case .A192GCM:
            return 192
        case .A256GCM, .A128CBC_HS256:
            return 256
        case .A192CBC_HS384:
            return 384
        case .A256CBC_HS512:
            return 512
        }
    }

    func encrypt(
        plaintext: Data,
        key: Data,
        iv: Data,
        aad: Data
    ) throws -> (ciphertext: Data, tag: Data) {
        try guardKeySize(key: key)
        switch self {
        case .A128GCM, .A192GCM, .A256GCM:
            return try aesGcmEncrypt(
                plaintext: plaintext,
                key: key,
                iv: iv,
                tagLen: tagLength,
                aad: aad
            )
        case .A128CBC_HS256, .A192CBC_HS384, .A256CBC_HS512:
            let hash = self == .A128CBC_HS256 ? Hash.SHA256
                : (self == .A192CBC_HS384 ? Hash.SHA384 : Hash.SHA512)
            let bothKeyLen = key.count / 2
            let (macKey, encKey) = (key[0 ..< bothKeyLen], key[bothKeyLen ..< key.count])
            return try aesCbcHmacSha2Encrypt(
                hash: hash,
                macKey: macKey,
                plaintext: plaintext,
                key: encKey,
                iv: iv,
                tagLen: tagLength,
                aad: aad
            )
        }
    }

    func decrypt(
        ciphertext: Data,
        key: Data,
        iv: Data,
        tag: Data,
        aad: Data
    ) throws -> Data {
        try guardKeySize(key: key)
        switch self {
        case .A128GCM, .A192GCM, .A256GCM:
            return try aesGcmDecrypt(ciphertext: ciphertext, key: key, iv: iv, tag: tag, aad: aad)
        case .A128CBC_HS256, .A192CBC_HS384, .A256CBC_HS512:
            let hash = self == .A128CBC_HS256 ? Hash.SHA256
                : (self == .A192CBC_HS384 ? Hash.SHA384 : Hash.SHA512)
            let bothKeyLen = key.count / 2
            let (macKey, encKey) = (key[0 ..< bothKeyLen], key[bothKeyLen ..< key.count])
            return try aesCbcHmacSha2Decrypt(
                hash: hash,
                macKey: macKey,
                ciphertext: ciphertext,
                key: encKey,
                iv: iv,
                tag: tag,
                aad: aad,
                authTagLen: tagLength
            )
        }
    }

    var ivBitSize: Int {
        switch self {
        case .A128GCM, .A192GCM, .A256GCM:
            return 96
        case .A128CBC_HS256, .A192CBC_HS384, .A256CBC_HS512:
            return 128
        }
    }

    var tagLength: Int {
        switch self {
        case .A128GCM, .A192GCM, .A256GCM, .A128CBC_HS256:
            return 16
        case .A192CBC_HS384:
            return 24
        case .A256CBC_HS512:
            return 32
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
