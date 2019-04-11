//
//  TestingUtils.swift
//  ECDHESSwift_Tests
//
//  Created by Jack Zhu on 2019/4/11.
//

import Foundation
import XCTest

public func XCTAssertNoThrow<T>(_ expression: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #file, line: UInt = #line, also validateResult: (T) -> Void) {
    func executeAndAssignResult(_ expression: @autoclosure () throws -> T, to: inout T?) rethrows {
        to = try expression()
    }
    var result: T?
    XCTAssertNoThrow(try executeAndAssignResult(expression, to: &result), message, file: file, line: line)
    if let r = result {
        validateResult(r)
    }
}

extension Data {
    func numberString() -> String {
        let format =  "%d"
        return map { String(format: format, $0) }.joined(separator: ", ")
    }
}
