//
//  EcdhEsJwe.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/17.
//

import Foundation
import JOSESwift

public struct EcdhEsJwe: JSONWebEncryption {
    
    static internal var encryptor: JWEEncryptor = EcdhEsEncryptor()
    
    static var defaultAlg = EcdhEsAlgorithm.ECDH_ES_A256KW
    
    static var defaultEnc = EncryptionAlgorithm.A256GCM
    
    let separator = "."
    
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
        let dot = separator.data(using: .ascii)!
        return self.header.jsonSerializedData().base64URLEncodedData()
            + dot + encryptedKey.base64URLEncodedData()
            + dot + initializationVector.base64URLEncodedData()
            + dot + ciphertext.base64URLEncodedData()
            + dot + authenticationTag.base64URLEncodedData()
    }
    
    public func decrypt(key: JWK) throws -> Data {
        return try EcdhEsJwe.encryptor.decrypt(
            key: key, header: header,
            encryptedKey: encryptedKey, iv: initializationVector,
            ciphertext: ciphertext, tag: authenticationTag,
            aad: additionalAuthenticatedData)
    }
    
    public init(plaintext: Data, pubKey :ECPublicKey, header: JSONWebEncryptionHeader, options: [String:Any] = [:]) throws {
        (self.header, self.encryptedKey, self.initializationVector, self.ciphertext, self.authenticationTag) =
            try EcdhEsJwe.encryptor.encrypt(plaintext: plaintext, key: pubKey, header: header, options: options)
        self.additionalAuthenticatedData = Data()
        if let aad = options["aad"] as? Data {
            self.additionalAuthenticatedData = aad
        }
    }
    
    public init(plaintext: Data, pubKey: ECPublicKey, headerDic: [String: Any] = [:], options: [String:Any] = [:]) throws {
        var header = headerDic
        if header["alg"] == nil {
            header["alg"] = EcdhEsJwe.defaultAlg.rawValue
        }
        if header["enc"] == nil {
            header["enc"] = EcdhEsJwe.defaultEnc.rawValue
        }
        let jweHeader = try EcdhEsJweHeader(parameters: header)
        try self.init(plaintext: plaintext, pubKey:pubKey, header: jweHeader, options: options)
    }
    
    public init(compactSerializedString: String) throws {
        let parts = compactSerializedString.components(separatedBy: separator)
        guard
            parts.count == 5,
            let headerJsonData = Data(base64URLEncoded: parts[0]) else {
                throw ECDHEESError.invalidCompactSerializedData
        }
        let h = try EcdhEsJweHeader(jsonData: headerJsonData)
        guard
            let encKey = Data(base64URLEncoded: parts[1]),
            let iv = Data(base64URLEncoded: parts[2]),
            let ct = Data(base64URLEncoded: parts[3]),
            let tag = Data(base64URLEncoded: parts[4])
            else {
                throw ECDHEESError.invalidCompactSerializedData
        }
        (self.header, self.encryptedKey, self.initializationVector, self.ciphertext, self.authenticationTag) =
            (h, encKey, iv, ct, tag)
        
        self.additionalAuthenticatedData = Data()
    }
    
    public init(compactSerializedData: Data) throws {
        guard let compactSerializedString = String(data: compactSerializedData, encoding: .ascii) else {
            throw ECDHEESError.invalidCompactSerializedData
        }
        try self.init(compactSerializedString: compactSerializedString)
    }
}
