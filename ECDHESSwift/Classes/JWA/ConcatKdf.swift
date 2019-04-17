//
//  ConcatKdf.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation

/**
 Concat KDF see https://tools.ietf.org/html/rfc7518#section-4.6.2

 - Parameter hash: HASH algorithm
 - Parameter z: The shared secret Z
 - Parameter keyDataLen: The number of bits in the desired output key.
 - Parameter algorithmID: AlgorithmID @See Section 5.8.1.2 of [NIST.800-56A]
 - Parameter partyUInfo: PartyUInfo @See Section 5.8.1.2 of [NIST.800-56A]
 - Parameter partyVInfo: PartyVInfo @See Section 5.8.1.2 of [NIST.800-56A]
 - Parameter suppPubInfo: SuppPubInfo @See Section 5.8.1.2 of [NIST.800-56A]
 - Parameter suppPrivInfo: SuppPrivInfo @See Section 5.8.1.2 of [NIST.800-56A]

 - Throws: ECDHError
 - Returns: Derived Keying Material
 **/
func concatKDF(
    _ hash: Hash,
    _ z: Data,
    _ keyDataLen: Int,
    _ algorithmID: Data,
    _ partyUInfo: Data,
    _ partyVInfo: Data,
    _ suppPubInfo: Data = Data(),
    _ suppPrivInfo: Data = Data()
) throws -> Data {
    if keyDataLen == 0 {
        return Data()
    }
    let modLen = keyDataLen % hash.bitLength
    let reps = (keyDataLen / hash.bitLength) + (modLen > 0 ? 1 : 0)

    let concatedData = z + algorithmID + partyUInfo + partyVInfo + suppPubInfo + suppPrivInfo
    let hashInputLen = 4 + concatedData.count
    guard hashInputLen <= 0xFFFF else {
        throw ECDHEESError.deriveKeyFail(reason: "Derivation parameter (couter + Z + otherInfor) is more than max HASH input length")
    }
    
    var derivedKeyingMaterial = Data()
    for i in 1 ..< reps {
        derivedKeyingMaterial += hash.digest(intToData(value: UInt32(i).bigEndian) + concatedData)
    }

    if modLen == 0 {
        derivedKeyingMaterial += hash.digest(intToData(value: UInt32(reps).bigEndian) + concatedData)
    } else {
        let digest = hash.digest(intToData(value: UInt32(reps).bigEndian) + concatedData)
        derivedKeyingMaterial += truncateBitLen(from: digest, bitLen: modLen)
    }
    return derivedKeyingMaterial
}
