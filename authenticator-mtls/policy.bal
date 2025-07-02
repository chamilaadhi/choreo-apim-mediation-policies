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

const CERTIFICATE_HEADER = "x-client-cert-x509";
json AUTHENTICATION_FALIURE_MESSAGE = {
    "error_message": "Invalid Credentials",
    "code": "900901",
    "error_description": "Make sure you have provided the correct security credentials."
};

@mediation:RequestFlow
public function addHeader_In(mediation:Context ctx, http:Request req, string Certificate\ Content\ part1, string Certificate\ Content\ part2, boolean Optional = false)
                                                                returns http:Response|false|error|() {

    string savedCertStringJoind = Certificate\ Content\ part1 + Certificate\ Content\ part2;
    string savedCertString = check url:decode(savedCertStringJoind, "UTF-8");
    io:println(savedCertString);

    string|http:HeaderNotFoundError incomingCertString = req.getHeader(CERTIFICATE_HEADER);

    if (incomingCertString is http:HeaderNotFoundError) {
        log:printDebug("MTLS Header not found");
        return generateResponse(AUTHENTICATION_FALIURE_MESSAGE, http:STATUS_UNAUTHORIZED);
    } else {
        string urlDecodedincomingCert = check url:decode(incomingCertString, "UTF-8");
        crypto:Certificate? incomingCert = check getCertificate(urlDecodedincomingCert);
        crypto:Certificate? savedCert = check getCertificate(savedCertString);

        if (incomingCert is crypto:Certificate && savedCert is crypto:Certificate &&
        incomingCert.issuer == savedCert.issuer && incomingCert.serial == savedCert.serial) {
            log:printDebug("Client certificate matches the saved certificate.");
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
