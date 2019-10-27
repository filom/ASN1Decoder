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

    var pkBlock: ASN1Object!

    init(pkBlock: ASN1Object) {
        self.pkBlock = pkBlock
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
}
