//
//  EcdhEsJweHeader.swift
//  CryptoSwift
//
//  Created by MFantcy on 2019/4/17.
//

import Foundation
import JOSESwift

public struct EcdhEsJweHeader: JSONWebEncryptionHeader {
    private var jsonData: Data

    private var parameters: [String: Any] {
        didSet {
            guard JSONSerialization.isValidJSONObject(parameters) else {
                // restore previous parameters state
                do {
                    guard
                        let params = try JSONSerialization.jsonObject(
                            with: jsonData,
                            options: [.mutableContainers]
                        ) as? [String: Any]
                    else {
                        return
                    }
                    parameters = params
                } catch {}
                return
            }
            jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
        }
    }

    public init(alg: String, enc: String) {
        parameters = ["alg": alg, "enc": enc]
        jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
    }

    public init(parameters: [String: Any]) throws {
        guard parameters["alg"] is String, parameters["enc"] is String else {
            throw ECDHEESError.invalidHeaderParameter(reason: "alg, enc")
        }
        var params = parameters
        for (k, v) in parameters {
            if v is JWK {
                params[k] = (v as! JWK).dictionarized()
            }
        }
        guard JSONSerialization.isValidJSONObject(params) else {
            throw ECDHEESError.invalidHeaderParameter(reason: "parameters dictionary contains unencodable data")
        }
        jsonData = try JSONSerialization.data(withJSONObject: params, options: [])
        self.parameters = params
    }

    public init(jsonData: Data) throws {
        guard let params = try JSONSerialization.jsonObject(with: jsonData, options: [.mutableContainers]) as? [String: Any] else {
            throw ECDHEESError.invalidJsonData
        }
        parameters = params
        self.jsonData = jsonData
    }

    public init(b64uData: Data) throws {
        guard let jsonData = Data(base64URLEncoded: b64uData) else {
            throw ECDHEESError.invalidBase64URLEncoded
        }
        try self.init(jsonData: jsonData)
    }

    public init(cloneFrom: JSONWebEncryptionHeader) throws {
        try self.init(jsonData: cloneFrom.jsonSerializedData())
    }

    public func jsonSerializedData() -> Data {
        return jsonData
    }

    public func allParameters() -> [String: Any] {
        return parameters
    }
}

// jwe params
extension EcdhEsJweHeader {
    public var alg: String {
        get { return self["alg"] as? String ?? "" }
        set { self["alg"] = newValue }
    }

    public var enc: String {
        get { return self["enc"] as? String ?? "" }
        set { self["enc"] = newValue }
    }

    public var epk: ECPublicKey? {
        get { return self["epk"] as? ECPublicKey ?? nil }
        set { self["epk"] = newValue }
    }

    public var apu: String? {
        get { return self["apu"] as? String ?? nil }
        set { self["apu"] = newValue }
    }

    public var apv: String? {
        get { return self["apv"] as? String ?? nil }
        set { self["apv"] = newValue }
    }
}

// subscript
extension EcdhEsJweHeader {
    public subscript(index: String) -> Any? {
        get {
            switch index {
            case "epk":
                if let epk = parameters["epk"] as? ECPublicKey {
                    return epk
                } else if let epkDic = parameters["epk"] as? [String: String] {
                    do {
                        return try ECPublicKey(dictionary: epkDic)
                    } catch {}
                    return nil
                }
            default: break
            }
            return parameters[index]
        }
        set {
            var toBeSetted = newValue
            switch index {
            case "alg", "enc": // alg and enc must be a String
                guard newValue is String else {
                    return
                }
            case "apu", "apv": // apu and apv must be a String or nil
                guard newValue == nil || newValue is String else {
                    return
                }
            default:
                if newValue is JWK {
                    toBeSetted = (newValue as! JWK).dictionarized()
                }
            }
            var param = parameters
            param[index] = toBeSetted
            parameters = param
        }
    }
}
