//
//  JWEEncryptor.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/17.
//

import Foundation
import JOSESwift

public protocol JWEEncryptor {
    func encrypt(plaintext: Data, key :JWK, header: JSONWebEncryptionHeader, options: [String:Any]) throws -> (header: JSONWebEncryptionHeader, encryptedKey: Data, iv: Data, ciphertext: Data, tag: Data)
    func decrypt(key: JWK, header: JSONWebEncryptionHeader, encryptedKey: Data, iv: Data, ciphertext: Data, tag: Data, aad: Data) throws -> Data
}

class EcdhEsEncryptor: JWEEncryptor {
    internal var keyAgreementCompute: (
        _ alg: EcdhEsAlgorithm,
        _ enc: EncryptionAlgorithm,
        _ privKey: ECPrivateKey,
        _ pubKey: ECPublicKey,
        _ apu: Data,
        _ apv: Data
        ) throws -> Data = ecdhKeyAgreementCompute
    
    internal var getRandomBytes: (_ size: Int) -> Data = randomBytes
    
    internal var createECKeyPair: (_ curveType: ECCurveType) throws -> ECKeyPair = generateECKeyPair
    
    func encrypt(plaintext: Data, key: JWK, header: JSONWebEncryptionHeader, options: [String : Any] = [:]) throws -> (header: JSONWebEncryptionHeader, encryptedKey: Data, iv: Data, ciphertext: Data, tag: Data) {
        
        guard
            let alg = EcdhEsAlgorithm(rawValue: header.alg),
            let enc = EncryptionAlgorithm(rawValue: header.enc)
        else {
            throw ECDHEESError.unknownOrUnsupportedAlgorithm(reason: "alg: \(header.alg), enc: \(header.enc)")
        }
        
        guard let staticPubKey = key as? ECPublicKey else {
            throw ECDHEESError.invalidJWK(reason: "key must be an ECPublicKey")
        }
        
        var ephemeralKeyPair: ECKeyPair
        if let eKeyPair = options["ephemeralKeyPair"] as? ECKeyPair {
            ephemeralKeyPair = eKeyPair
        } else {
            ephemeralKeyPair = try createECKeyPair(staticPubKey.crv)
        }
        let apu = Data(base64Encoded: header.apu ?? "") ?? Data()
        let apv = Data(base64Encoded: header.apv ?? "") ?? Data()
        
        let kek = try keyAgreementCompute(alg, enc, ephemeralKeyPair.getPrivate(), staticPubKey, apu, apv)
        var cek: Data, encryptedKey: Data
        if let keyWrapAlgorithm = alg.keyWrapAlgorithm {
            if let injectedKey = options["key"] as? Data {
                cek = injectedKey
            } else {
                cek = getRandomBytes(enc.keySize / 8)
            }
            encryptedKey = try keyWrapAlgorithm.wrap(kek: kek, rawKey: cek)
        } else {
            cek = kek
            encryptedKey = Data()
        }

        let iv = options["iv"] as? Data ?? getRandomBytes(enc.ivSize / 8)
        
        var resHeader = try EcdhEsJweHeader(cloneFrom: header)
        resHeader.epk = ephemeralKeyPair.getPublic()
        
        var aad = resHeader.jsonSerializedData().base64URLEncodedData()
        if let extAad = options["aad"] as? Data {
            aad += ".".data(using: .ascii)! + extAad
        }
        aad += options["aad"] as? Data ?? Data()
        
        let (ciphertext, tag) = try enc.encrypt(plaintext: plaintext, key: cek, iv: iv, tagLen: enc.tagLength / 8, aad: aad)
        
        return (resHeader, encryptedKey, iv, ciphertext, tag)
    }
    
    func decrypt(key: JWK, header: JSONWebEncryptionHeader, encryptedKey: Data, iv: Data, ciphertext: Data, tag: Data, aad: Data = Data()) throws -> Data {
        
        guard
            let alg = EcdhEsAlgorithm(rawValue: header.alg),
            let enc = EncryptionAlgorithm(rawValue: header.enc)
            else {
                throw ECDHEESError.unknownOrUnsupportedAlgorithm(reason: "alg: \(header.alg), enc: \(header.enc)")
        }
        
        guard let staticPrivKey = key as? ECPrivateKey else {
            throw ECDHEESError.invalidJWK(reason: "key must be an ECPrivateKey")
        }
        guard let ephemeralPubKey = header.epk else {
            throw ECDHEESError.invalidJWK(reason: "missing ephemeral public key in header")
        }
        
        let apu = Data(base64Encoded: header.apu ?? "") ?? Data()
        let apv = Data(base64Encoded: header.apv ?? "") ?? Data()
        
        let kek = try keyAgreementCompute(alg, enc, staticPrivKey, ephemeralPubKey, apu, apv)
        
        var cek: Data
        if let keyWrapAlgorithm = alg.keyWrapAlgorithm {
            cek = try keyWrapAlgorithm.unwrap(kek: kek, wrappedKey: encryptedKey)
        } else {
            cek = kek
        }
        
        let decryptionAad = header.jsonSerializedData().base64URLEncodedData()
        + ((aad.count > 0) ? ".".data(using: .ascii)! + aad : aad)
        
        return try enc.decrypt(ciphertext: ciphertext, key: cek, iv: iv, tag: tag, aad: decryptionAad)
    }
}
