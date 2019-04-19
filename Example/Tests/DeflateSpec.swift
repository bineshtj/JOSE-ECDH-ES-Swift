//
//  DeflateSpec.swift
//  ECDHESSwift_Tests
//
//  Created by MFantcy on 2019/4/19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

@testable import ECDHESSwift
import Nimble
import Quick

class DeflateSpec: QuickSpec {
    override func spec() {
        describe("compress and decompress") {
            it("test case from ietf-jose/cookbook/jwe/5_9.compressed_content.json should ok") {
                
                let data = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!

                let expectedCompressed = "bY_BDcIwDEVX-QNU3QEOrIA4pqlDokYxchxVvbEDGzIJbioOSJwc-f___HPjBu8KVFpVtAplVE1-wZo0YjNZo3C7R5v72pV5f5X382VWjYQpqZKAyjziZOr2B7kQPSy6oZIXUnDYbVKN4jNXi2u0yB7t1qSHTjmMODf9QgvrDzfTIQXnyQRuUya4zIWG3vTOdir0v7BRHFYWq3k1k1A_gSDJqtcBF-GZxw8"

                print("length: ", data.count)
                let compressed = try! deflateCompress(data)
                expect(compressed.base64URLEncodedString()) == expectedCompressed
                let decompressed = try! deflateDecompress(compressed)
                expect(decompressed) == data
            }
        }
    }
}
