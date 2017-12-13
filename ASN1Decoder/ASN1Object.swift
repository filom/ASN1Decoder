//
//  ASN1Object.swift
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


public class ASN1Object : CustomStringConvertible {
    
    init() {
    }
    
    /// This property contains the DER encoded object
    public var rawValue: Data?
    
    /// This property contains the decoded Swift object whenever is possible
    public var value: Any?
    
    
    public var identifier: ASN1Identifier?
    
    var sub: [ASN1Object]?
    
    weak var parent: ASN1Object?
    
    public func sub(_ index: Int) -> ASN1Object? {
        if let sub = self.sub, index >= 0 && index < sub.count {
            return sub[index]
        }
        return nil
    }
    
    public func subCount() -> Int {
        return sub?.count ?? 0
    }
    
    public func findOid(_ oid: String) -> ASN1Object? {
        for child in sub ?? [] {
            if child.identifier?.tagNumber() == .objectIdentifier {
                if child.value as? String == oid {
                    return child
                }
            } else {
                if let result = child.findOid(oid) {
                    return result
                }
            }
        }
        return nil
    }
    
    public var description: String {
        return printAsn1()
    }
    
    fileprivate func printAsn1(insets: String = "") -> String {
        var output = insets
        output.append(identifier?.description.uppercased() ?? "")
        output.append(value != nil ? " : \(value!)" : "")
        if identifier?.typeClass() == .universal, identifier?.tagNumber() == .objectIdentifier {
            if let descr = ASN1Object.oidDecodeMap[value as? String ?? ""] {
                output.append(" (\(descr))")
            }
        }
        output.append(sub != nil && sub!.count > 0 ? " {" : "")
        output.append("\n")
        for item in sub ?? [] {
            output.append(item.printAsn1(insets: insets + "    "))
        }
        output.append(sub != nil && sub!.count > 0 ? insets + "}\n" : "")
        return output
    }
    
    
    static let oidDecodeMap:[String:String] = [
        "0.4.0.1862.1.1" : "etsiQcsCompliance",
        "0.4.0.1862.1.3" : "etsiQcsRetentionPeriod",
        "0.4.0.1862.1.4" : "etsiQcsQcSSCD",
        "1.2.840.10040.4.1" : "dsa",
        "1.2.840.10045.2.1" : "ecPublicKey",
        "1.2.840.10045.3.1.7" : "prime256v1",
        "1.2.840.10045.4.3.2" : "ecdsaWithSHA256",
        "1.2.840.10045.4.3.4" : "ecdsaWithSHA512",
        "1.2.840.113549.1.1.1" : "rsaEncryption",
        "1.2.840.113549.1.1.4" : "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" : "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" : "sha256WithRSAEncryption",
        "1.2.840.113549.1.7.1" : "data",
        "1.2.840.113549.1.7.2" : "signedData",
        "1.2.840.113549.1.9.1" : "emailAddress",
        "1.2.840.113549.1.9.16.2.47" : "signingCertificateV2",
        "1.2.840.113549.1.9.3" : "contentType",
        "1.2.840.113549.1.9.4" : "messageDigest",
        "1.2.840.113549.1.9.5" : "signingTime",
        "1.3.6.1.4.1.11129.2.4.2" : "certificateExtension",
        "1.3.6.1.4.1.311.60.2.1.2" : "jurisdictionOfIncorporationSP",
        "1.3.6.1.4.1.311.60.2.1.3" : "jurisdictionOfIncorporationC",
        "1.3.6.1.5.5.7.1.1" : "authorityInfoAccess",
        "1.3.6.1.5.5.7.1.3" : "qcStatements",
        "1.3.6.1.5.5.7.2.1" : "cps",
        "1.3.6.1.5.5.7.2.2" : "unotice",
        "1.3.6.1.5.5.7.3.1" : "serverAuth",
        "1.3.6.1.5.5.7.3.2" : "clientAuth",
        "1.3.6.1.5.5.7.48.1" : "ocsp",
        "1.3.6.1.5.5.7.48.2" : "caIssuers",
        "1.3.6.1.5.5.7.9.1" : "dateOfBirth",
        "2.16.840.1.101.3.4.2.1" : "sha-256",
        "2.16.840.1.113733.1.7.23.6" : "VeriSign EV policy",
        "2.23.140.1.1" : "extendedValidation",
        "2.23.140.1.2.2" : "extendedValidation",
        "2.5.29.14" : "subjectKeyIdentifier",
        "2.5.29.15" : "keyUsage",
        "2.5.29.17" : "subjectAltName",
        "2.5.29.18" : "issuerAltName",
        "2.5.29.19" : "basicConstraints",
        "2.5.29.31" : "cRLDistributionPoints",
        "2.5.29.32" : "certificatePolicies",
        "2.5.29.35" : "authorityKeyIdentifier",
        "2.5.29.37" : "extKeyUsage",
        "2.5.29.9" : "subjectDirectoryAttributes",
        "2.5.4.10" : "organizationName",
        "2.5.4.11" : "organizationalUnitName",
        "2.5.4.15" : "businessCategory",
        "2.5.4.17" : "postalCode",
        "2.5.4.3" : "commonName",
        "2.5.4.4" : "surname",
        "2.5.4.42" : "givenName",
        "2.5.4.46" : "dnQualifier",
        "2.5.4.5" : "serialNumber",
        "2.5.4.6" : "countryName",
        "2.5.4.7" : "localityName",
        "2.5.4.8" : "stateOrProvinceName",
        "2.5.4.9" : "streetAddress"
    ]
    

}


