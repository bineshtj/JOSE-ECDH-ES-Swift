//
//  EcdhEsJwe.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/17.
//

import Foundation
import JOSESwift

public struct EcdhEsJwe: JSONWebEncryption {
    internal static var encryptor: JWEEncryptor = EcdhEsEncryptor()

    static var defaultAlg = EcdhEsAlgorithm.ECDH_ES_A256KW

    static var defaultEnc = EncryptionAlgorithm.A256GCM

    public let header: JSONWebEncryptionHeader

    public let encryptedKey: Data

    public let initializationVector: Data

    public var ciphertext: Data

    public var authenticationTag: Data

    public var additionalAuthenticatedData: Data

    public var compactSerializedString: String {
        return String(data: compactSerializedData, encoding: .ascii)!
    }

    public var compactSerializedData: Data {
        let separator = Data([0x2E])
        return header.jsonSerializedData().base64URLEncodedData()
            + separator + encryptedKey.base64URLEncodedData()
            + separator + initializationVector.base64URLEncodedData()
            + separator + ciphertext.base64URLEncodedData()
            + separator + authenticationTag.base64URLEncodedData()
    }

    public func decrypt(key: JWK) throws -> Data {
        return try EcdhEsJwe.encryptor.decrypt(
            key: key, header: header,
            encryptedKey: encryptedKey, iv: initializationVector,
            ciphertext: ciphertext, tag: authenticationTag,
            aad: additionalAuthenticatedData)
    }

    public func decrypt(privKeyJwkJson: Data) throws -> Data {
        let key = try ECPrivateKey(data: privKeyJwkJson)
        return try EcdhEsJwe.encryptor.decrypt(
            key: key, header: header,
            encryptedKey: encryptedKey, iv: initializationVector,
            ciphertext: ciphertext, tag: authenticationTag,
            aad: additionalAuthenticatedData)
    }

    public func decrypt(privKeyJwkJson: String) throws -> Data {
        guard let jsonData = privKeyJwkJson.data(using: .utf8) else {
            throw ECDHEESError.invalidJWK(reason: "unexpected jwk json data")
        }
        return try decrypt(privKeyJwkJson: jsonData)
    }

    /**
     Encrypt plaintext as a ECDH-ES JWE

     - Parameter plaintext: plaintext
     - Parameter pubKeyJwkJson: EC public JWK JSON data
     - Parameter header: JSONWebEncryptionHeader
     - Parameter options: encryption option (e.g ["aad": Data(......)])

     - Throws: ECDHError

     **/
    public init(plaintext: Data, pubKeyJwkJson: Data, header: JSONWebEncryptionHeader, options: [String: Any] = [:]) throws {
        let pubKey = try ECPublicKey(data: pubKeyJwkJson)
        try self.init(plaintext: plaintext, pubKey: pubKey, header: header, options: options)
    }

    /**
     Encrypt plaintext as a ECDH-ES JWE

     - Parameter plaintext: plaintext
     - Parameter pubKeyJwkJson: EC public JWK JSON string
     - Parameter header: JSONWebEncryptionHeader
     - Parameter options: encryption option (e.g ["aad": Data(......)])

     - Throws: ECDHError

     **/
    public init(plaintext: Data, pubKeyJwkJson: String, header: JSONWebEncryptionHeader, options: [String: Any] = [:]) throws {
        guard let jsonData = pubKeyJwkJson.data(using: .utf8) else {
            throw ECDHEESError.invalidJWK(reason: "unexpected jwk json data")
        }
        let pubKey = try ECPublicKey(data: jsonData)
        try self.init(plaintext: plaintext, pubKey: pubKey, header: header, options: options)
    }

    /**
     Encrypt plaintext as a ECDH-ES JWE

     - Parameter plaintext: plaintext
     - Parameter pubKey: ECPublicKey
     - Parameter header: JSONWebEncryptionHeader
     - Parameter options: encryption option (e.g ["aad": Data(......)])

     - Throws: ECDHError

     **/
    public init(plaintext: Data, pubKey: ECPublicKey, header: JSONWebEncryptionHeader, options: [String: Any] = [:]) throws {
        (self.header, encryptedKey, initializationVector, ciphertext, authenticationTag) =
            try EcdhEsJwe.encryptor.encrypt(plaintext: plaintext, key: pubKey, header: header, options: options)
        additionalAuthenticatedData = Data()
        if let aad = options["aad"] as? Data {
            additionalAuthenticatedData = aad
        }
    }

    /**
     Encrypt plaintext as a ECDH-ES JWE

     - Parameter plaintext: plaintext
     - Parameter pubKeyJwkJson: EC public JWK JSON data
     - Parameter headerDic: JOSE header dictionary
     - Parameter options: encryption option (e.g ["aad": Data(......)])

     - Throws: ECDHError

     **/
    public init(plaintext: Data, pubKeyJwkJson: Data, headerDic: [String: Any] = [:], options: [String: Any] = [:]) throws {
        let pubKey = try ECPublicKey(data: pubKeyJwkJson)
        try self.init(plaintext: plaintext, pubKey: pubKey, headerDic: headerDic, options: options)
    }

    /**
     Encrypt plaintext as a ECDH-ES JWE

     - Parameter plaintext: plaintext
     - Parameter pubKeyJwkJson: EC public JWK JSON string
     - Parameter headerDic: JOSE header dictionary
     - Parameter options: encryption option (e.g ["aad": Data(......)])

     - Throws: ECDHError

     **/
    public init(plaintext: Data, pubKeyJwkJson: String, headerDic: [String: Any] = [:], options: [String: Any] = [:]) throws {
        guard let jsonData = pubKeyJwkJson.data(using: .utf8) else {
            throw ECDHEESError.invalidJWK(reason: "unexpected jwk json data")
        }
        let pubKey = try ECPublicKey(data: jsonData)
        try self.init(plaintext: plaintext, pubKey: pubKey, headerDic: headerDic, options: options)
    }

    /**
     Encrypt plaintext as a ECDH-ES JWE

     - Parameter plaintext: plaintext
     - Parameter pubKey: ECPublicKey
     - Parameter headerDic: JOSE header dictionary
     - Parameter options: encryption option (e.g ["aad": Data(......)])

     - Throws: ECDHError

     **/
    public init(plaintext: Data, pubKey: ECPublicKey, headerDic: [String: Any] = [:], options: [String: Any] = [:]) throws {
        var header = headerDic
        if header["alg"] == nil {
            header["alg"] = EcdhEsJwe.defaultAlg.rawValue
        }
        if header["enc"] == nil {
            header["enc"] = EcdhEsJwe.defaultEnc.rawValue
        }
        let jweHeader = try EcdhEsJweHeader(parameters: header)
        try self.init(plaintext: plaintext, pubKey: pubKey, header: jweHeader, options: options)
    }

    /**
     Create ECDH-ES JWE with a compact serialized string for decrypt

     - Parameter compactSerializedString: compact serialized string

     - Throws: ECDHError

     **/
    public init(compactSerializedString: String) throws {
        guard let compactSerializedData = compactSerializedString.data(using: .ascii) else {
            throw ECDHEESError.invalidCompactSerializedData
        }
        try self.init(compactSerializedData: compactSerializedData)
    }

    /**
     Create ECDH-ES JWE with a compact serialized data for decrypt

     - Parameter compactSerializedData: compact serialized data

     - Throws: ECDHError

     **/
    public init(compactSerializedData: Data) throws {
        let parts = compactSerializedData.split(separator: UInt8(0x2E), omittingEmptySubsequences: false)
        guard
            parts.count == 5,
            let header = Data(base64URLEncoded: parts[0]),
            let encryptedKey = Data(base64URLEncoded: parts[1]),
            let iv = Data(base64URLEncoded: parts[2]),
            let ciphertext = Data(base64URLEncoded: parts[3]),
            let tag = Data(base64URLEncoded: parts[4])
        else {
            throw ECDHEESError.invalidCompactSerializedData
        }
        self.header = try EcdhEsJweHeader(jsonData: header)
        (self.encryptedKey, initializationVector, self.ciphertext, authenticationTag)
            = (encryptedKey, iv, ciphertext, tag)

        additionalAuthenticatedData = Data()
    }
}
