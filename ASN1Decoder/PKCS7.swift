//
//  PKCS7.swift
//
//  Copyright © 2017 Filippo Maguolo.
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


public class PKCS7 {
    
    private var derData: Data!
    private var asn1: [ASN1Object]!
    private var mainBlock: ASN1Object!
    
    private let OID_Data = "1.2.840.113549.1.7.1"
    private let OID_SignedData = "1.2.840.113549.1.7.2"
    
    public init(data: Data) throws {
        
        derData = data
        
        asn1 = try ASN1DERDecoder.decode(data: derData)
        
        guard asn1.count > 0 && asn1[0].sub?[0].value as? String == OID_SignedData else {
            throw PKCS7Error.parseError
        }
        
        mainBlock = asn1[0].sub?[1].sub?[0]
    }
    
    
    
    public var digestAlgorithm: String? {
        return asn1[0].sub?[0].value as? String
    }
    
    
    public var certificate: X509Certificate? {
        if let blockSigner = mainBlock.sub?[3].sub {
            return X509Certificate(asn1: blockSigner)
        }
        return nil
    }
    
    
    public var data: Data? {
        if let block = mainBlock.findOid(OID_Data) {
            if let dataBlock = block.parent?.sub?.last?.sub?[0] {
                if dataBlock.value == nil {
                    var out = Data()
                    for chunk in dataBlock.sub ?? [] {
                        if let value = chunk.rawValue {
                            out.append(value)
                        }
                    }
                    return out
                }
                else {
                    return dataBlock.value as? Data
                }
            }
        }
        return nil
    }
    
    
}



enum PKCS7Error: Error {
    case parseError
}

