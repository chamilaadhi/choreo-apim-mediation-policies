// Copyright (c) 2025 WSO2 LLC (http://www.wso2.org) All Rights Reserved.
//
// WSO2 LLC licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import choreo/mediation;
import ballerina/http;
import ballerina/io;
import ballerina/url;
import ballerina/crypto;
import ballerina/random;
import ballerina/log;
import ballerina/file;
import ballerina/time;

const CERTIFICATE_HEADER = "x-client-cert-x509";
json AUTHENTICATION_FALIURE_MESSAGE = {
    "error_message": "Invalid Credentials",
    "code": "900901",
    "error_description": "Make sure you have provided the correct security credentials."
};

map<crypto:Certificate?> requestCertsMap = {};
map<crypto:Certificate?> savedCertsMap = {};

@mediation:RequestFlow
public function addHeader_In(mediation:Context ctx, http:Request req, string Certificate\ Content, boolean Optional = false)
                                                                returns http:Response|false|error|() {

    string savedCertString = check url:decode(Certificate\ Content, "UTF-8");

    string|http:HeaderNotFoundError incomingCertString = req.getHeader(CERTIFICATE_HEADER);
  
    if (incomingCertString is http:HeaderNotFoundError) {
        log:printDebug("MTLS Header not found");
        if (Optional) {
            log:printDebug("MTLS Header is optional, returning without error.");
            return ();
        }
        return generateResponse(AUTHENTICATION_FALIURE_MESSAGE, http:STATUS_UNAUTHORIZED);
    } else {
        crypto:Certificate? incomingCert;
        if requestCertsMap.hasKey(incomingCertString) {
            incomingCert = requestCertsMap[incomingCertString];
            log:printDebug("Incoming certificate found in the map: " + incomingCertString);
        } else {
            // If the certificate is not in the map, we need to parse it
            string urlDecodedincomingCert = check url:decode(incomingCertString, "UTF-8");
            incomingCert = check getCertificate(urlDecodedincomingCert);
            // add to map for future use
            requestCertsMap[incomingCertString] = incomingCert; 
            log:printDebug("Incoming certificate not found in the map, parsing and adding to the map: " + incomingCertString);
        }
        crypto:Certificate? savedCert;
        if savedCertsMap.hasKey(savedCertString) {
            savedCert = savedCertsMap[savedCertString];
            log:printDebug("Saved certificate found in the map: " + savedCertString);
        } else {
            // If the certificate is not in the map, we need to parse it
            savedCert = check getCertificate(savedCertString);
            // and store it for future use.
            savedCertsMap[savedCertString] = savedCert;
            log:printDebug("Saved certificate not found in the map, parsing and adding to the map: " + savedCertString);
        }

        if (incomingCert is crypto:Certificate && savedCert is crypto:Certificate &&
        incomingCert.signature == savedCert.signature) {
            log:printDebug("Client certificate matches the saved certificate.");
            // validate expires and notBefore dates
            time:Utc current = time:utcNow();
            if (time:utcDiffSeconds(current, incomingCert.notBefore) < 0d) || 
                    (time:utcDiffSeconds(current, incomingCert.notAfter) > 0d) {
                log:printDebug("Client certificate has expired or is not valid yet.");
                // remove expired certificate from the map
                _ = requestCertsMap.remove(incomingCertString);
                _ = savedCertsMap.remove(savedCertString);
                return generateResponse(AUTHENTICATION_FALIURE_MESSAGE, http:STATUS_UNAUTHORIZED);
            }
        } else {
            log:printDebug("Client certificate does not match the saved certificate.");
            return generateResponse(AUTHENTICATION_FALIURE_MESSAGE, http:STATUS_UNAUTHORIZED);
        }
    }
    return ();
}

function getCertificate(string certificateString) returns error|crypto:Certificate? {
    int randomInteger = check random:createIntInRange(1, 100000);
    string tempfile = "/tmp/" + randomInteger.toString() + "_temp-cert.crt";
    io:Error? result = io:fileWriteString(tempfile, certificateString);
    if (result is error) {
        log:printError("Error writing to file '" + tempfile + "': ", result);
    } else {
        log:printDebug("Successfully wrote string to '" + tempfile + "'");
        crypto:PublicKey incomingPublicKey = check crypto:decodeRsaPublicKeyFromCertFile(tempfile);
        check file:remove(tempfile);
        crypto:Certificate? incomingCert = incomingPublicKey.certificate;
        return incomingCert;
    }
    return;
}

function generateResponse(json payload, int statusCode) returns http:Response {
    http:Response response = new ();
    response.setJsonPayload(payload);
    response.statusCode = statusCode;
    return response;
}
