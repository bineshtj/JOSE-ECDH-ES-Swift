//
//  JWEHeader.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation
import JOSESwift

public protocol JSONWebEncryptionHeader {
    var alg: String { get }
    var enc: String { get }
    var epk: ECPublicKey? { get }
    var apu: String? { get }
    var apv: String? { get }
    subscript(index: String) -> Any? { get }
    func jsonSerializedData() -> Data
}

public struct EcdhEsJweHeader: JSONWebEncryptionHeader {
    private var jsonData: Data
    private var parameters: [String: Any]
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

    public init(alg: String, enc: String) {
        parameters = ["alg": alg, "enc": enc]
        jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
    }
    
    public init(parameters: [String: Any]) throws {
        self.parameters = parameters
        jsonData = try JSONSerialization.data(withJSONObject: self.parameters, options: [])
    }
    
    public init(jsonData: Data) throws {
        self.jsonData = jsonData
        guard let params = try JSONSerialization.jsonObject(with: jsonData, options: [.mutableContainers]) as? [String: Any] else {
            throw ECDHEESrror.invalidJsonData
        }
        parameters = params
    }
    
    public subscript(index: String) -> Any? {
        get {
            switch index {
            case "epk":
                if let epk = parameters["epk"] as? ECPublicKey {
                    return epk
                }
                guard
                    let epkDic = parameters["epk"] as? [String: String],
                    let kty = epkDic["kty"],
                    kty == "EC",
                    let crv = epkDic["crv"],
                    let x = epkDic["crv"],
                    let y = epkDic["crv"],
                    let curve = ECCurveType(rawValue: crv)
                else {
                    return nil
                }
                return ECPublicKey(crv: curve, x: x, y: y, additionalParameters: epkDic)
            default:
                return parameters[index]
            }
        }
        set {
            switch index {
            case "alg", "enc":
                guard newValue is String else {
                    return
                }
            case "apu", "apv":
                guard newValue == nil || newValue is String else {
                    return
                }
            case "epk":
                guard newValue == nil || newValue is ECPublicKey else {
                    return
                }
            default:
                guard newValue == nil || newValue is Encodable else {
                    return
                }
            }
            parameters[index] = newValue
            jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
        }
    }
    
    public func jsonSerializedData() -> Data {
        return jsonData
    }
}
