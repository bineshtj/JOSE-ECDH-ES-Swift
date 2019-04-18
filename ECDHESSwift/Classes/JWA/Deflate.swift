//
//  Deflate.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/18.
//

import Compression
import Foundation

func deflateCompress(_ data: Data) throws -> Data {
    guard let result = performCompression(
        algorithm: COMPRESSION_ZLIB,
        operation: COMPRESSION_STREAM_ENCODE,
        src: Array([UInt8](data)),
        srcSize: data.count
    ) else {
        throw ECDHEESError.compressionFailed
    }
    return result
}

func deflateDecompress(_ data: Data) throws -> Data {
    guard let result = performCompression(
        algorithm: COMPRESSION_ZLIB,
        operation: COMPRESSION_STREAM_DECODE,
        src: Array([UInt8](data)),
        srcSize: data.count
    ) else {
        throw ECDHEESError.decompressionFailed
    }
    return result
}

private typealias Config = (operation: compression_stream_operation, algorithm: compression_algorithm)

private func performCompression(
    algorithm: compression_algorithm,
    operation: compression_stream_operation,
    src: UnsafePointer<UInt8>,
    srcSize: Int
) -> Data? {
    guard
        srcSize > 0
    else { return Data() }

    let streamPrt = UnsafeMutablePointer<compression_stream>.allocate(capacity: 1)
    defer { streamPrt.deallocate() }
    var stream = streamPrt.pointee

    guard
        COMPRESSION_STATUS_ERROR != compression_stream_init(&stream, operation, algorithm)
    else { return nil }
    
    defer { compression_stream_destroy(&stream) }

    let bufferSize = min(srcSize, 512)
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
    defer { buffer.deallocate() }

    stream.dst_ptr = buffer
    stream.dst_size = bufferSize
    stream.src_ptr = src
    stream.src_size = srcSize

    var result = Data()
    let flags: Int32 = Int32(COMPRESSION_STREAM_FINALIZE.rawValue)

    while true {
        switch compression_stream_process(&stream, flags) {
        case COMPRESSION_STATUS_OK:
            guard stream.dst_size == 0 else { return nil }
            result.append(buffer, count: stream.dst_ptr - buffer)
            stream.dst_ptr = buffer
            stream.dst_size = bufferSize

        case COMPRESSION_STATUS_END:
            result.append(buffer, count: stream.dst_ptr - buffer)
            return result

        default:
            return nil
        }
    }
}
