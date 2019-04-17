//
//  KeyWrapSpec.swift
//  ECDHESSwift_Tests
//
//  Created by MFantcy on 2019/4/16.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

@testable import ECDHESSwift

import Quick
import Nimble

class KeyWrapSpec: QuickSpec {
    let keyWrapTestVectors = [
        [
            "title": "Wrap 128 bits of Key Data with a 128-bit KEK",
            "kek": "000102030405060708090A0B0C0D0E0F",
            "rawKey":       "00112233445566778899AABBCCDDEEFF",
            "wrappedKey":  "1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5"
        ],
        [
            "title": "Wrap 128 bits of Key Data with a 192-bit KEK",
            "kek": "000102030405060708090A0B0C0D0E0F1011121314151617",
            "rawKey":       "00112233445566778899AABBCCDDEEFF",
            "wrappedKey":  "96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D"
        ],
        [
            "title": "Wrap 128 bits of Key Data with a 256-bit KEK",
            "kek": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "rawKey":       "00112233445566778899AABBCCDDEEFF",
            "wrappedKey":  "64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7"
        ],
        [
            "title": "Wrap 192 bits of Key Data with a 192-bit KEK",
            "kek": "000102030405060708090A0B0C0D0E0F1011121314151617",
            "rawKey":       "00112233445566778899AABBCCDDEEFF0001020304050607",
            "wrappedKey":  "031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2"
        ],
        [
            "title": "Wrap 192 bits of Key Data with a 256-bit KEK",
            "kek": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "rawKey":       "00112233445566778899AABBCCDDEEFF0001020304050607",
            "wrappedKey":  "A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1"
        ],
        [
            "title": "Wrap 256 bits of Key Data with a 256-bit KEK",
            "kek": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "rawKey":       "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
            "wrappedKey":  "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21"
        ]
    ]
    
    override func spec() {
        
        describe("Key Wrap Test Vectors Test") {
            for vector in keyWrapTestVectors {
                it(vector["title"]!) {
                    let kek = Data(hex: vector["kek"]!)
                    let rawKey = Data(hex: vector["rawKey"]!)
                    let expected = Data(hex: vector["wrappedKey"]!)
                    let wrappedKey = try! keyWrap(kek: kek, key: rawKey)
                    expect(wrappedKey).to(equal(expected), description: """
                        
                    expected: \(expected.numberString())
                    actual:   \(wrappedKey.numberString())
""")
                }
            }
        }
        
        describe("Key Unwrap Test Vectors Test") {
            for vector in keyWrapTestVectors {
                it(vector["title"]!) {
                    let kek = Data(hex: vector["kek"]!)
                    let expected = Data(hex: vector["rawKey"]!)
                    let wrappedKey = Data(hex: vector["wrappedKey"]!)
                    let rawKey = try! keyUnwrap(kek: kek, encryptedKey: wrappedKey)
                    expect(rawKey).to(equal(expected), description: """
                        
                        expected: \(expected.numberString())
                        actual:   \(wrappedKey.numberString())
                        """)
                }
            }
        }
        
    }
}
