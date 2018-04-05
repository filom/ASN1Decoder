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


public class X509Certificate : CustomStringConvertible {
    
    private var derData: Data!
    private var asn1: [ASN1Object]!
    private var block1: ASN1Object!
    
    private let beginPemBlock = "-----BEGIN CERTIFICATE-----"
    private let endPemBlock   = "-----END CERTIFICATE-----"
    
    private let OID_KeyUsage = "2.5.29.15"
    private let OID_ExtendedKeyUsage = "2.5.29.37"
    private let OID_SubjectAltName = "2.5.29.17"
    private let OID_IssuerAltName = "2.5.29.18"
    
    enum X509BlockPosition : Int {
        case version = 0
        case serialNumber = 1
        case signatureAlg = 2
        case issuer = 3
        case dateValidity = 4
        case subject = 5
        case publicKey = 6
        case extensions = 7
    }
    
    public init(data: Data) throws {
        
        derData = data
        
        decodePemToDer()
        
        asn1 = try ASN1DERDecoder.decode(data: derData)
        
        guard asn1.count > 0 else {
            throw ASN1Error.parseError
        }
        
        block1 = asn1[0].sub(0)
    }
    
    init(asn1: ASN1Object) {
        self.asn1 = [asn1]
        block1 = asn1.sub(0)
    }
    
    public var description: String {
        var str = ""
        asn1.forEach({
            str += $0.description
            str += "\n"
        })
        return str
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
        return block1[X509BlockPosition.serialNumber]?.value as? Data
    }
    
    
    /// Returns the issuer (issuer distinguished name) value from the certificate as a String.
    public var issuerDistinguishedName: String? {
        if let issuerBlock = block1[X509BlockPosition.issuer] {
            return blockDistinguishedName(block: issuerBlock)
        }
        return nil
    }
    
    
    public var issuerOIDs: [String] {
        var result: [String] = []
        if let subjectBlock = block1[X509BlockPosition.issuer] {
            for sub in subjectBlock.sub ?? [] {
                if let value = firstLeafValue(block: sub) as? String {
                    result.append(value)
                }
            }
        }
        return result
    }
    
    public func issuer(oid: String) -> String? {
        if let subjectBlock = block1[X509BlockPosition.issuer] {
            if let oidBlock = subjectBlock.findOid(oid) {
                return oidBlock.parent?.sub?.last?.value as? String
            }
        }
        return nil
    }
    
    
    /// Returns the subject (subject distinguished name) value from the certificate as a String.
    public var subjectDistinguishedName: String? {
        if let subjectBlock = block1[X509BlockPosition.subject] {
            return blockDistinguishedName(block: subjectBlock)
        }
        return nil
    }
    
    public var subjectOIDs: [String] {
        var result: [String] = []
        if let subjectBlock = block1[X509BlockPosition.subject] {
            for sub in subjectBlock.sub ?? [] {
                if let value = firstLeafValue(block: sub) as? String {
                    result.append(value)
                }
            }
        }
        return result
    }
    
    public func subject(oid: String) -> String? {
        if let subjectBlock = block1[X509BlockPosition.subject] {
            if let oidBlock = subjectBlock.findOid(oid) {
                return oidBlock.parent?.sub?.last?.value as? String
            }
        }
        return nil
    }
    
    
    /// Gets the notBefore date from the validity period of the certificate.
    public var notBefore: Date? {
        return block1[X509BlockPosition.dateValidity]?.sub(0)?.value as? Date
    }
    
    
    /// Gets the notAfter date from the validity period of the certificate.
    public var notAfter: Date? {
        return block1[X509BlockPosition.dateValidity]?.sub(1)?.value as? Date
    }
    
    
    /// Gets the signature value (the raw signature bits) from the certificate.
    public var signature: Data? {
        return asn1[0].sub(2)?.value as? Data
    }
    
    
    /// Gets the signature algorithm name for the certificate signature algorithm.
    public var sigAlgName: String? {
        return ASN1Object.oidDecodeMap[sigAlgOID ?? ""]
    }
    
    
    /// Gets the signature algorithm OID string from the certificate.
    public var sigAlgOID: String? {
        return block1.sub(2)?.sub(0)?.value as? String
    }
    
    
    /// Gets the DER-encoded signature algorithm parameters from this certificate's signature algorithm.
    public var sigAlgParams: Data? {
        return nil
    }
    
    
    /**
     Gets a boolean array representing bits of the KeyUsage extension, (OID = 2.5.29.15).
     ```
     KeyUsage ::= BIT STRING {
     digitalSignature        (0),
     nonRepudiation          (1),
     keyEncipherment         (2),
     dataEncipherment        (3),
     keyAgreement            (4),
     keyCertSign             (5),
     cRLSign                 (6),
     encipherOnly            (7),
     decipherOnly            (8)
     }
     ```
     */
    public var keyUsage: [Bool] {
        var result: [Bool] = []
        if let oidBlock = block1.findOid(OID_KeyUsage) {
            let data = oidBlock.parent?.sub?.last?.sub(0)?.value as? Data
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
        return extensionObject(oid: OID_ExtendedKeyUsage)?.valueAsStrings ?? []
    }
    
    
    /// Gets a collection of subject alternative names from the SubjectAltName extension, (OID = 2.5.29.17).
    public var subjectAlternativeNames: [String] {
        return extensionObject(oid: OID_SubjectAltName)?.valueAsStrings ?? []
    }
    
    
    /// Gets a collection of issuer alternative names from the IssuerAltName extension, (OID = 2.5.29.18).
    public var issuerAlternativeNames: [String] {
        return extensionObject(oid: OID_IssuerAltName)?.valueAsStrings ?? []
    }
    
    
    /// Gets the informations of the public key from this certificate.
    public var publicKey: PublicKey? {
        if let pkBlock = block1[X509BlockPosition.publicKey] {
            return PublicKey(pkBlock: pkBlock)
        }
        return nil
    }
    
    
    
    /// Get a list of critical extension OID codes
    public var criticalExtensionOIDs: [String] {
        var result: [String] = []
        for extBlock in extensionBlocks ?? [] {
            let ext = X509Extension(block: extBlock)
            if ext.isCritical, let oid = ext.oid {
                result.append(oid)
            }
        }
        return result
    }
    
    
    /// Get a list of non critical extension OID codes
    public var nonCriticalExtensionOIDs: [String] {
        var result: [String] = []
        for extBlock in extensionBlocks ?? [] {
            let ext = X509Extension(block: extBlock)
            if !ext.isCritical, let oid = ext.oid {
                result.append(oid)
            }
        }
        return result
    }
    
    private var extensionBlocks: [ASN1Object]? {
        return block1.sub?.count ?? 0 > 6 ? block1[X509BlockPosition.extensions]?.sub(0)?.sub : nil
    }
    
    
    /// Gets the extension information of the given OID code.
    public func extensionObject(oid: String) -> X509Extension? {
        if block1.sub?.count ?? 0 > 6 {
            if let extBlock = block1[X509BlockPosition.extensions]?.findOid(oid) {
                return X509Extension(block: extBlock.parent!)
            }
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
                    let quote = value.contains(where: { specialChar.contains($0) }) ? "\"" : ""
                    result.append(quote)
                    result.append(value)
                    result.append(quote)
                }
            }
        }
        return result
    }
    
    
    // read possibile PEM encoding
    private func decodePemToDer() {
        if let pem = String(data: derData, encoding: .ascii), pem.contains(beginPemBlock) {
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
    }
}

public class PublicKey {
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
        guard let algOid = algOid, let keyData = pkBlock.sub(1)?.value as? Data else {
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
    
    private let OID_ECPublicKey = "1.2.840.10045.2.1"
    private let OID_RSAEncryption = "1.2.840.113549.1.1.1"
}


public class X509Extension {
    var block: ASN1Object!
    
    init(block: ASN1Object) {
        self.block = block
    }
    
    public var oid: String? {
        return block.sub(0)?.value as? String
    }
    
    public var name: String? {
        return ASN1Object.oidDecodeMap[oid ?? ""]
    }
    
    public var isCritical: Bool {
        if block.sub?.count ?? 0 > 2 {
            return block.sub(1)?.value as? Bool ?? false
        }
        return false
    }
    
    public var value: Any? {
        if let valueBlock = block.sub?.last {
            return firstLeafValue(block: valueBlock)
        }
        return nil
    }
    
    var valueAsBlock: ASN1Object? {
        return block.sub?.last
    }
    
    var valueAsStrings: [String] {
        var result: [String] = []
        for item in block.sub?.last?.sub ?? [] {
            if let name = item.value as? String {
                result.append(name)
            }
        }
        return result
    }
    
    
}




private func firstLeafValue(block: ASN1Object) -> Any? {
    if let sub = block.sub, sub.count > 0 {
        return firstLeafValue(block: sub[0])
    }
    return block.value
}


extension ASN1Object {
    
    subscript(index: X509Certificate.X509BlockPosition) -> ASN1Object? {
        if index.rawValue < sub?.count ?? 0 {
            return sub?[index.rawValue]
        }
        return nil
    }
    
}

