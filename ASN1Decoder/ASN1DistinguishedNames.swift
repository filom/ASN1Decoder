//
//  ASN1DistinguishedNames.swift
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

public class ASN1DistinguishedNames {
    
    public let oid: String
    public let representation: String
    
    init(oid: String, representation: String) {
        self.oid = oid
        self.representation = representation
    }
   
    public static let commonName             = ASN1DistinguishedNames(oid: "2.5.4.3",  representation: "CN")
    public static let dnQualifier            = ASN1DistinguishedNames(oid: "2.5.4.46", representation: "DNQ")
    public static let serialNumber           = ASN1DistinguishedNames(oid: "2.5.4.5",  representation: "SERIALNUMBER")
    public static let givenName              = ASN1DistinguishedNames(oid: "2.5.4.42", representation: "GIVENNAME")
    public static let surname                = ASN1DistinguishedNames(oid: "2.5.4.4",  representation: "SURNAME")
    public static let organizationalUnitName = ASN1DistinguishedNames(oid: "2.5.4.11", representation: "OU")
    public static let organizationName       = ASN1DistinguishedNames(oid: "2.5.4.10", representation: "O")
    public static let streetAddress          = ASN1DistinguishedNames(oid: "2.5.4.9",  representation: "STREET")
    public static let localityName           = ASN1DistinguishedNames(oid: "2.5.4.7",  representation: "L")
    public static let stateOrProvinceName    = ASN1DistinguishedNames(oid: "2.5.4.8",  representation: "ST")
    public static let countryName            = ASN1DistinguishedNames(oid: "2.5.4.6",  representation: "C")
    public static let email                  = ASN1DistinguishedNames(oid: "1.2.840.113549.1.9.1", representation: "E")
    
}
