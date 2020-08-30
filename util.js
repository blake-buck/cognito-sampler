require('dotenv').config();
const crypto = require('crypto');
const { AWS_COGNITO_SECRET_HASH, AWS_CLIENT_ID } = process.env;

function createSecretHash(username){
    return crypto.createHmac('sha256', AWS_COGNITO_SECRET_HASH).update(username + AWS_CLIENT_ID).digest('base64')
}

function formatHeaders(headers){
    let newHeaders = [];

    for(const headerName in headers){
        newHeaders.push({
            headerName,
            headerValue: headers[headerName]
        });
    }

    return newHeaders;
}

module.exports = {
    createSecretHash,
    formatHeaders
}