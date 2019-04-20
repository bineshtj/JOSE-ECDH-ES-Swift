//
//  ECDHKeyAgreement.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation
import JOSESwift

func ecdhKeyAgreementCompute(
    alg: EcdhEsAlgorithm,
    enc: EncryptionAlgorithm,
    privKey: ECPrivateKey,
    pubKey: ECPublicKey,
    apu: Data,
    apv: Data
) throws -> Data {
    let z = try ecdhDeriveBits(ecPrivJwk: privKey, ecPubJwk: pubKey)
    var algId: Data, keyDataLen: Int
    if alg == .ECDH_ES {
        algId = enc.rawValue.data(using: .utf8)!
        keyDataLen = enc.keyBitSize
    } else {
        algId = alg.rawValue.data(using: .utf8)!
        keyDataLen = alg.keyWrapAlgorithm!.keyBitSize
    }
    let algorithmID = prefixedBigEndenLen(from: algId)
    let partyUInfo = prefixedBigEndenLen(from: apu)
    let partyVInfo = prefixedBigEndenLen(from: apv)
    let suppPubInfo = intToData(value: UInt32(keyDataLen).bigEndian)
    return try concatKDF(Hash.SHA256, z, keyDataLen, algorithmID, partyUInfo, partyVInfo, suppPubInfo)
}
