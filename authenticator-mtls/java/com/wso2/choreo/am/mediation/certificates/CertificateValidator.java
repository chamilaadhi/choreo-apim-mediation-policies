/*
 * Copyright (c) 2025, WSO2 LLc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein is strictly forbidden, unless permitted by WSO2 in accordance with
 * the WSO2 Commercial License available at http://wso2.com/licenses.
 * For specific language governing the permissions and limitations under
 * this license, please see the license as well as any agreement you’ve
 * entered into with WSO2 governing the purchase of this software and any
 * associated services.
 */
package com.wso2.choreo.am.mediation.certificates;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertificateValidator {

	public static ValidationResponse verifyCertificates(String savedCertString, String clientCertString) {
		ValidationResponse response = new ValidationResponse();

		try {
			X509Certificate savedCert = getCertificate(savedCertString);
			X509Certificate clientCert = getCertificate(clientCertString);
			
			try {
				// verify the certificate
				clientCert.verify(savedCert.getPublicKey());
				// validate the expiration
				clientCert.checkValidity();
				response.setVerify(true);
				
			} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
				response.setVerify(false);
				response.setMessage("Error while verifying the certificate " + e.getMessage());
			}
		} catch (CertificateException | IOException e) {
			response.setVerify(false);
			response.setMessage("Error while parsing the certificate " + e.getMessage());
		} 

		return response;
	}

	public static X509Certificate getCertificate(String base64encodedCertString)
			throws CertificateException, IOException {

		String base64Encoded = base64encodedCertString.replace("-----BEGIN CERTIFICATE-----", "")
				.replace("-----END CERTIFICATE-----", "").replaceAll("\\s", ""); // Removes newlines, spaces, etc.

		if (base64Encoded.isEmpty()) {
			throw new CertificateException("PEM string does not contain certificate data.");
		}

		byte[] decodedBytes;
		try {
			decodedBytes = Base64.getDecoder().decode(base64Encoded);
		} catch (IllegalArgumentException e) {
			throw new CertificateException("Failed to decode Base64 from PEM string", e);
		}

		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		try (InputStream is = new ByteArrayInputStream(decodedBytes)) {
		    return (X509Certificate) factory.generateCertificate(is);
		}

	}
	

}
