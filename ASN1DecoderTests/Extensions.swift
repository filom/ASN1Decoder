//
//  Extensions.swift
//  ASN1DecoderTests
//
//  Created by Filippo Maguolo on 17/09/2023.
//  Copyright © 2023 Filippo Maguolo. All rights reserved.
//

import Foundation

extension Data {
    func hexEncodedString(separation: String = "") -> String {
        return reduce("") {$0 + String(format: "%02X\(separation)", $1)}
    }
}

extension String {
    func dataFromBase64() -> Data? {
        Data(base64Encoded: self, options: .ignoreUnknownCharacters)
    }
}

