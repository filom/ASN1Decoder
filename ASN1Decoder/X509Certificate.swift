//
//  X509Certificate.swift
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


public class X509Certificate {
    
    private var derData: Data!
    private var asn1: [ASN1Object]!
    private var block1: ASN1Object!
    
    private let beginPemBlock = "-----BEGIN CERTIFICATE-----"
    private let endPemBlock   = "-----END CERTIFICATE-----"
    
    public init(data: Data) throws {
        
        derData = data
        
        // read possibile PEM encoding
        if let pem = String(data: data, encoding: .ascii), pem.contains(beginPemBlock) {
            let lines = pem.components(separatedBy: .newlines)
            var base64buffer  = ""
            var certLine = false
            for line in lines {
                if line == endPemBlock  {
                    certLine = false
                }
                if certLine {
                    base64buffer.append(line)
                }
                if line == beginPemBlock  {
                    certLine = true
                }
            }
            if let derDataDecoded = Data(base64Encoded: base64buffer) {
                derData = derDataDecoded
            }
        }
        
        asn1 = try ASN1DERDecoder.decode(data: derData)
        block1 = asn1[0].sub![0]
    }
    
    
    /// Checks that the given date is within the certificate's validity period.
    public func checkValidity(_ date: Date = Date()) -> Bool {
        if let notBefore = notBefore, let notAfter = notAfter {
            return date > notBefore && date < notAfter
        }
        return false
    }
    
    
    /// Gets the version (version number) value from the certificate.
    public var version: Int? {
        if let v = firstLeafValue(block: block1) as? Data, let i = v.toIntValue() {
            return Int(i) + 1
        }
        return nil
    }
    
    
    /// Gets the serialNumber value from the certificate.
    public var serialNumber: Data? {
        return block1.sub?[1].value as? Data
    }
    
    
    /// Returns the issuer (issuer distinguished name) value from the certificate as a String.
    public var issuerDistinguishedName: String? {
        if let issuerBlock = block1.sub?[3] {
            return blockDistinguishedName(block: issuerBlock)
        }
        return nil
    }
    
    
    /// Returns the subject (subject distinguished name) value from the certificate as a String.
    public var subjectDistinguishedName: String? {
        if let subjectBlock = block1.sub?[5] {
            return blockDistinguishedName(block: subjectBlock)
        }
        return nil
    }
    
    
    
    /// Gets the notBefore date from the validity period of the certificate.
    public var notBefore: Date? {
        return block1.sub?[4].sub?[0].value as? Date
    }
    
    
    /// Gets the notAfter date from the validity period of the certificate.
    public var notAfter: Date? {
        return block1.sub?[4].sub?[1].value as? Date
    }
    
    
    /// Gets the signature value (the raw signature bits) from the certificate.
    public var signature: Data? {
        return asn1[0].sub?[2].value as? Data
    }
    
    
    /// Gets the signature algorithm name for the certificate signature algorithm.
    public var sigAlgName: String? {
        return ASN1Object.oidDecodeMap[sigAlgOID ?? ""]
    }
    
    
    /// Gets the signature algorithm OID string from the certificate.
    public var sigAlgOID: String? {
        return block1.sub?[2].sub?[0].value as? String
    }
    
    
    ///    Gets the DER-encoded signature algorithm parameters from this certificate's signature algorithm.
    public var sigAlgParams: Data? {
        return nil
    }
    
    /*
        Gets a boolean array representing bits of the KeyUsage extension, (OID = 2.5.29.15).
         
        KeyUsage ::= BIT STRING {
            digitalSignature        (0),
            nonRepudiation          (1), -- recent editions of X.509 have renamed this bit to contentCommitment
            keyEncipherment         (2),
            dataEncipherment        (3),
            keyAgreement            (4),
            keyCertSign             (5),
            cRLSign                 (6),
            encipherOnly            (7),
            decipherOnly            (8) 
        }
    */
    public var keyUsage: [Bool] {
        var result: [Bool] = []
        if let oidBlock = block1.findOid("2.5.29.15") {
            let data = oidBlock.parent?.sub?.last?.sub?[0].value as? Data
            let bits: UInt8 = data?.first ?? 0
            for i in 0...7 {
                let value = bits & UInt8(1 << i) != 0
                result.insert(value, at: 0)
            }
        }
        return result
    }
    
    
    /// Gets a list of Strings representing the OBJECT IDENTIFIERs of the ExtKeyUsageSyntax field of the extended key usage extension, (OID = 2.5.29.37).
    public var extendedKeyUsage: [String] {
        var result: [String] = []
        if let oidBlock = block1.findOid("2.5.29.37") {
            for item in oidBlock.parent?.sub?.last?.sub?[0].sub ?? [] {
                if let name = item.value as? String {
                    result.append(name)
                }
            }
        }
        return result
    }
    
    
    // TODO
    /// Gets the certificate constraints path length from the critical BasicConstraints extension, (OID = 2.5.29.19).
    var basicConstraints: Int? {
        return nil
    }
    
    
    /// Gets a collection of subject alternative names from the SubjectAltName extension, (OID = 2.5.29.17).
    public var subjectAlternativeNames: [String] {
        var result: [String] = []
        if let oidBlock = block1.findOid("2.5.29.17") {
            for item in oidBlock.parent?.sub?.last?.sub?[0].sub ?? [] {
                if let name = item.value as? String {
                    result.append(name)
                }
            }
        }
        return result
    }
    
    
    /// Gets a collection of issuer alternative names from the IssuerAltName extension, (OID = 2.5.29.18).
    public var issuerAlternativeNames: [String] {
        var result: [String] = []
        if let oidBlock = block1.findOid("2.5.29.18") {
            for item in oidBlock.parent?.sub?.last?.sub?[0].sub ?? [] {
                if let name = item.value as? String {
                    result.append(name)
                }
            }
        }
        return result
    }
    
    
    
    
    /// Gets the informations of the public key from this certificate.
    public var publicKey: PublicKey? {
        if let pkBlock = block1.sub?[6] {
            return PublicKey(pkBlock: pkBlock)
        }
        return nil
    }
    
    
    
    
    
    
    // Format subject/issuer information in RFC1779
    private func blockDistinguishedName(block: ASN1Object) -> String {
        var result = ""
        let oidNames = [
            ["2.5.4.3",  "CN"],           // commonName
            ["2.5.4.46", "DNQ"],          // dnQualifier
            ["2.5.4.5",  "SERIALNUMBER"], // serialNumber
            ["2.5.4.42", "GIVENNAME"],    // givenName
            ["2.5.4.4",  "SURNAME"],      // surname
            ["2.5.4.11", "OU"],           // organizationalUnitName
            ["2.5.4.10", "O"],            // organizationName
            ["2.5.4.9",  "STREET"],       // streetAddress
            ["2.5.4.7",  "L"],            // localityName
            ["2.5.4.8",  "ST"],           // stateOrProvinceName
            ["2.5.4.6",  "C"],            // countryName
            ["1.2.840.113549.1.9.1", "E"] // e-mail
        ]
        for oidName in oidNames {
            if let oidBlock = block.findOid(oidName[0]) {
                if !result.isEmpty {
                    result.append(", ")
                }
                result.append(oidName[1])
                result.append("=")
                if let value = oidBlock.parent?.sub?.last?.value as? String {
                    let specialChar = ",+=\n<>#;\\"
                    let quote = value.characters.contains(where: { specialChar.characters.contains($0) }) ? "\"" : ""
                    result.append(quote)
                    result.append(value)
                    result.append(quote)
                }
            }
        }
        return result
    }

}

public class PublicKey {
    var pkBlock: ASN1Object!
    
    init(pkBlock: ASN1Object) {
        self.pkBlock = pkBlock
    }
    
    var algOid: String? {
        return pkBlock.sub?[0].sub?[0].value as? String
    }
    
    var algName: String? {
        return ASN1Object.oidDecodeMap[algOid ?? ""]
    }
    
    var algParams: String? {
        return pkBlock.sub?[0].sub?[1].value as? String
    }
    
    var key: Data? {
        if let keyBlock = pkBlock.sub?.last {
            if let keyBlockValue = firstLeafValue(block: keyBlock) as? Data {
                do {
                    let asn1PkBlock = try ASN1DERDecoder.decode(data: keyBlockValue)
                    print(asn1PkBlock)
                    return firstLeafValue(block: asn1PkBlock[0]) as? Data
                } catch {
                    return keyBlockValue
                }
            }
        }
        return nil
    }
}




private func firstLeafValue(block: ASN1Object) -> Any? {
    if let sub = block.sub, sub.count > 0 {
        return firstLeafValue(block: sub[0])
    }
    return block.value
}



