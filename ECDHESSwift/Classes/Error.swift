//
//  Error.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/10.
//

internal enum ECDHEESError: Error {
    case unknownOrUnsupportedAlgorithm(reason: String)
    case unknownOrUnsupportedCompressionAlgorithm(reason: String)
    case invalidJWK(reason: String)
    case invalidKeyDerivationSize
    case invalidKeySize
    case invalidEncryptionIVSize
    case invalidHeaderParameter(reason: String)
    case invalidJsonData
    case invalidBase64URLEncoded
    case invalidCompactSerializedData
    case deriveKeyFail(reason: String)
    case wrapKeyFail
    case unwrapKeyFail
    case compressionFailed
    case decompressionFailed
    case decryptFail(reason: String)
}
