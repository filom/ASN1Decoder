//
//  X509PublicKey.swift
//
//  Copyright © 2019 Filippo Maguolo.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

import Foundation

public class X509PublicKey {
    
    private let OID_ECPublicKey = "1.2.840.10045.2.1"
    private let OID_RSAEncryption = "1.2.840.113549.1.1.1"

    private static let beginPemBlock = "-----BEGIN PUBLIC KEY-----"
    private static let endPemBlock   = "-----END PUBLIC KEY-----"
    
    var asn1:[ASN1Object]
    var pkBlock: ASN1Object!

    init(pkBlock: ASN1Object)   {
        self.asn1 = [pkBlock]
        self.pkBlock = pkBlock
    }
    
    public convenience init(data: Data) throws {
        if String(data: data, encoding: .utf8)?.contains(X509PublicKey.beginPemBlock) ?? false {
            try self.init(pem: data)
        } else {
            try self.init(der: data)
        }
    }

    public init(der: Data) throws {
        asn1 = try ASN1DERDecoder.decode(data: der)
        guard asn1.count > 0,
            let pkBlock = asn1.first?.sub(1) else {
                throw ASN1Error.parseError
        }
        self.pkBlock = pkBlock
    }
    
    public convenience init(pem: Data) throws {
        guard let derData = X509PublicKey.decodeToDER(pem: pem) else {
            throw ASN1Error.parseError
        }

        try self.init(der: derData)
    }
    
    public var algOid: String? {
        return pkBlock.sub(0)?.sub(0)?.value as? String
    }

    public var algName: String? {
        return ASN1Object.oidDecodeMap[algOid ?? ""]
    }

    public var algParams: String? {
        return pkBlock.sub(0)?.sub(1)?.value as? String
    }

    public var key: Data? {
        guard
            let algOid = algOid,
            let keyData = pkBlock.sub(1)?.value as? Data else {
                return nil
        }

        switch algOid {
        case OID_ECPublicKey:
            return keyData

        case OID_RSAEncryption:
            guard let publicKeyAsn1Objects = (try? ASN1DERDecoder.decode(data: keyData)) else {
                return nil
            }
            guard let publicKeyModulus = publicKeyAsn1Objects.first?.sub(0)?.value as? Data else {
                return nil
            }
            return publicKeyModulus

        default:
            return nil
        }
    }
    
    func encodedKey() -> Data? {
        let  keyData = self.asn1.first?.rawValue
        var length = UInt16(keyData!.count).bigEndian
        return Data([UInt8(0x30),UInt8(0x82)]) + Data(bytes: &length, count: 2) + (keyData!)
    }
    
    // read possibile PEM encoding
    private static func decodeToDER(pem pemData: Data) -> Data? {
        if
            let pem = String(data: pemData, encoding: .ascii),
            pem.contains(beginPemBlock) {

            let lines = pem.components(separatedBy: .newlines)
            var base64buffer  = ""
            var certLine = false
            for line in lines {
                if line == endPemBlock {
                    certLine = false
                }
                if certLine {
                    base64buffer.append(line)
                }
                if line == beginPemBlock {
                    certLine = true
                }
            }
            if let derDataDecoded = Data(base64Encoded: base64buffer) {
                return derDataDecoded
            }
        }

        return nil
    }
}
