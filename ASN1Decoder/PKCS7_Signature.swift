//
//  File.swift
//  
//
//  Created by Alex - SEEMOO on 19.06.20.
//

import Foundation

extension PKCS7 {
    public var signatures: [Data]? {
        guard let block = mainBlock.findOid(.pkcs7signedData) else {return nil}
        
        //Signer infos sequence. https://tools.ietf.org/html/rfc5652#section-5.3
        guard let signerInfos = block.sub(5) else {return nil}
        let numberOfSignatures = signerInfos.subCount()
        
        #if DEBUG
        print(numberOfSignatures)
        print(signerInfos.description)
        #endif
        
        return nil
        
    }
}
