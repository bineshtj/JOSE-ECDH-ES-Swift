//
//  Error.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/10.
//

internal enum ECDHEESError: Error {
    case deriveKeyFail(reason: String)
    case invalidKeyDerivationSize
    case wrapKeyFail
    case unwrapKeyFail
    case invalidEncryptionKeySize
    case invalidEncryptionIVSize
    case invalidHeaderParameter(param: String)
    case invalidJsonData
    case invalidCompactSerializedData
    case unknownOrUnsupportedAlgorithm(reason: String)
    case invalidJWK(reason: String)
    
}
