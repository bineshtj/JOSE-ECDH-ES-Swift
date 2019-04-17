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
                return
            }
            jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
        }
    }
    
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
        self.parameters = ["alg": alg, "enc": enc]
        self.jsonData = try! JSONSerialization.data(withJSONObject: parameters, options: [])
    }
    
    public init(parameters: [String: Any]) throws {
        guard parameters["alg"] is String, parameters["enc"] is String else {
            throw ECDHEESError.invalidHeaderParameter(param: "alg, enc")
        }
        // TODO epk
        
        self.jsonData = try JSONSerialization.data(withJSONObject: parameters, options: [])
        self.parameters = parameters
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
    
    fileprivate mutating func updateEpk(_ value: Any?) {
        var toBeValue: Any?
        if let epk = value as? ECPublicKey {
            guard let epkJsonData = epk.jsonData() else {
                return
            }
            do {
                toBeValue = try JSONSerialization.jsonObject(with: epkJsonData, options: [.mutableContainers])
            } catch {
                return
            }
        } else if value == nil || value is [String:String] {
            toBeValue = value
        } else {
            return
        }
        var param = parameters
        param["epk"] = toBeValue
        parameters = param
    }
    
    fileprivate func getEpk() -> ECPublicKey? {
        if let epk = parameters["epk"] as? ECPublicKey {
            return epk
        } else if let epkDic = parameters["epk"] as? [String: String] {
            guard
                let kty = epkDic["kty"],
                kty == "EC",
                let crv = epkDic["crv"],
                let curve = ECCurveType(rawValue: crv),
                let x = epkDic["x"],
                let y = epkDic["y"]
            else {
                return nil
            }
            return ECPublicKey(crv: curve, x: x, y: y, additionalParameters: epkDic)
        }
        return nil
    }
    
    public subscript(index: String) -> Any? {
        get {
            switch index {
            case "epk":
                return getEpk()
            default:
                return parameters[index]
            }
        }
        set {
            var toBeSetted = newValue
            switch index {
            case "alg", "enc": //alg and enc must be a String
                guard newValue is String else {
                    return
                }
            case "apu", "apv": //apu and apv must be a String or nil
                guard newValue == nil || newValue is String else {
                    return
                }
            case "epk":
                if let epk = newValue as? ECPublicKey {
                    guard let epkJsonData = epk.jsonData() else {
                        return
                    }
                    do {
                        toBeSetted = try JSONSerialization.jsonObject(with: epkJsonData, options: [.mutableContainers])
                    } catch {
                        return
                    }
                } else if newValue != nil && !(newValue is [String:String]) {
                    return
                }
            default:
                guard newValue == nil || JSONSerialization.isValidJSONObject(newValue!) else {
                    return
                }
            }
            var param = self.parameters
            param[index] = toBeSetted
            self.parameters = param
        }
    }
    
    public func jsonSerializedData() -> Data {
        return jsonData
    }
    
    public func allParameters() -> [String:Any] {
        return self.parameters
    }
}
