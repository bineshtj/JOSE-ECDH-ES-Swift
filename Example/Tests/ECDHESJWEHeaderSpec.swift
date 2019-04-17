//
//  ECDHESJWEHeaderSpec.swift
//  ECDHESSwift_Tests
//
//  Created by MFantcy on 2019/4/16.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Quick
import Nimble
import ECDHESSwift
import JOSESwift

class ECDHESJWEHeaderSpec: QuickSpec {
    override func spec() {
        describe("normal header") {
            it("from jsonData should ok") {
                let jweHeaderData = """
{
    "alg":"ECDH-ES",
    "enc":"A128GCM",
    "apu":"QWxpY2U",
    "apv":"Qm9i",
    "epk":
    {
        "kty":"EC",
        "crv":"P-256",
        "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
        "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
    }
}
""".data(using: .utf8)!
                let header = try! EcdhEsJweHeader(jsonData: jweHeaderData)
                expect(header.alg) == "ECDH-ES"
                expect(header.enc) == "A128GCM"
                expect(header.apu) == "QWxpY2U"
                expect(header.apv) == "Qm9i"
                expect(header.epk).to(beAKindOf(ECPublicKey.self))
                expect(header.alg).to(equal(header["alg"]! as? String))
                expect(header.enc).to(equal(header["enc"]! as? String))
                expect(header.apu).to(equal(header["apu"]! as? String))
                expect(header.apv).to(equal(header["apv"]! as? String))
                expect(header["epk"]).to(beAKindOf(ECPublicKey.self))
            }
        }
    }
}
