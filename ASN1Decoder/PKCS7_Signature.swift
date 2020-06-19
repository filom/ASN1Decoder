//
//  File.swift
//  
//
//  Created by Alex - SEEMOO on 19.06.20.
//

import Foundation

extension PKCS7 {
    public var signatures: [SignatureInfo]? {
        //Signer infos sequence. https://tools.ietf.org/html/rfc5652#section-5.3
        
        guard let signerInfos = mainBlock.sub(4) else {return nil}
        
        let numberOfSignatures = signerInfos.subCount()
        
        var signatures = [SignatureInfo]()
        
        for i in 0..<numberOfSignatures {
            guard let signatureInfoasn1 = signerInfos.sub(i) else {continue}
            let sigInfo = SignatureInfo(asn1: signatureInfoasn1)
            signatures.append(sigInfo)
        }
        
        
        
        return signatures
        
    }
}

/// Signature info for a PKCS7 file
/// https://tools.ietf.org/html/rfc5652#section-5.3
public class SignatureInfo {
    
    /// The version of the Signature info. Should be 1
    public let version: ASN1Object?
    /// Contains information about the signing certificate, like commonName, OU, organization, country
    public let signerIdentifier: ASN1Object?
    /// The identifier for the algorithm that was used to sign
    public let digestAlgorithmIdentifier: ASN1Object?
    /// Contains information how the signature was created. A set with a sequence. First entry is the hashing algorithm. Second is the signature algorithm (not sure if this is valid for all pkcs files)
    public let signedAttributes: ASN1Object?
    /// Algorithm used to create the signature
    public let signatureAlgorithm: ASN1Object?
    /// The actual signature
    public let signature: ASN1Object?
    
    public var signatureData: Data? {
        return signature?.value as? Data
    }
    
    public var disgestAlgorithmName: String? {
        guard let oid = self.digestAlgorithmOID else {return nil}
        
        return String(describing: oid)
    }
    
    public var digestAlgorithmOID: OID? {
        let value = digestAlgorithmIdentifier?.sub(0)?.value as? String ?? ""
        return OID(rawValue: value)
    }
    
    public var signatureAlgorithmName: String? {
        guard let oid = self.signatureAlgorithmOID else {return nil}
        
        return String(describing: oid)
    }
    
    public var signatureAlgorithmOID: OID? {
        let value = signatureAlgorithm?.sub(0)?.value as? String ?? ""
        return OID(rawValue: value)
    }
    
    public init(asn1: ASN1Object) {
        version = asn1.sub(0)
        signerIdentifier = asn1.sub(1)
        digestAlgorithmIdentifier = asn1.sub(2)
        signedAttributes = asn1.sub(3)
        signatureAlgorithm = asn1.sub(4)
        signature = asn1.sub(5)
    }
}
