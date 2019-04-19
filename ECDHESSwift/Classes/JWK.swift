//
//  EcJwk.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/9.
//

import Foundation
import JOSESwift
import Security

public extension ECCurveType {
    var bitLength: Int {
        switch self {
        case .P256:
            return 256
        case .P384:
            return 384
        case .P521:
            return 521
        }
    }
}

enum EcKeyError: Error {
    case generateECKeyPairFail
}

public extension ECPrivateKey {
    func getPublic() -> ECPublicKey {
        return ECPublicKey(crv: crv, x: x, y: y, additionalParameters: parameters)
    }

    func isCorrespondWith(_ key: ECPublicKey) -> Bool {
        guard
            crv == key.crv,
            x == key.x,
            y == key.y
        else {
            return false
        }
        return true
    }
}

public extension ECKeyPair {
    func getPrivate() -> ECPrivateKey {
        return self as ECPrivateKey
    }
}

public func generateECKeyPair(curveType: ECCurveType) throws -> ECKeyPair {
    let attributes: [String: Any] = [kSecAttrKeySizeInBits as String: curveType.bitLength,
                                     kSecAttrKeyType as String: kSecAttrKeyTypeEC,
                                     kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]]
    var error: Unmanaged<CFError>?
    if let eckey: SecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
        return try ECPrivateKey(privateKey: eckey, additionalParameters: ["kid": UUID().uuidString])
    }
    throw EcKeyError.generateECKeyPairFail
}

public extension JWK {
    func dictionarized() -> [String: String] {
        do {
            guard
                let jsonData = self.jsonData(),
                let dic = try JSONSerialization.jsonObject(
                    with: jsonData,
                    options: [.mutableContainers]
                ) as? [String: String]
            else {
                return [String: String]()
            }
            return dic
        } catch {}
        return [String: String]()
    }

    init(dictionary: [String: Any]) throws {
        let jsonData = try JSONSerialization.data(withJSONObject: dictionary, options: [])
        try self.init(data: jsonData)
    }
}
