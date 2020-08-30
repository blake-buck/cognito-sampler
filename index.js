require('dotenv').config();
const express = require('express');
const {json} = express;

const {CognitoIdentityServiceProvider} = require('aws-sdk');
const {createSecretHash, formatHeaders} = require('./util');

const app = express();
app.use(express.static('client'))
app.use(json());

const {
    AWS_SECRET_ACCESS_KEY,
    AWS_ACCESS_KEY_ID,
    AWS_REGION,
    AWS_CLIENT_ID,
    AWS_USER_POOL_ID,
    SERVER_NAME
} = process.env;

const cognito = new CognitoIdentityServiceProvider({
    secretAccessKey: AWS_SECRET_ACCESS_KEY, 
    accessKeyId: AWS_ACCESS_KEY_ID, 
    region: AWS_REGION
});


app.post('/register', async (req, res) => {
    const {username, password} = req.body;

    const params = {
        ClientId:AWS_CLIENT_ID,
        Username:username,
        Password:password,
        SecretHash:createSecretHash(username)
    }

    try{
        const result = await cognito.signUp(params).promise()
        res.json({message:'Check your email for a code/link', result})
    }
    catch(error){
        res.json({message:'An error occured registration.', error})
    }
});

app.post('/confirm-register', async (req, res) => {
    const {username, confirmationCode} = req.body;

    const params = {
        ClientId: AWS_CLIENT_ID,
        Username: username,
        ConfirmationCode: confirmationCode,
        SecretHash:createSecretHash(username)
    }

    try{
        const result = await cognito.confirmSignUp(params).promise();
        res.json({message:'Registration confirmed.', result});
    }
    catch(error){
        res.json({message:'An error occured confirming registration', error});
    }
})

app.post('/login', async (req, res) => {
    const {username, password} = req.body;

    const params = {
        AuthFlow:   'ADMIN_USER_PASSWORD_AUTH',
        UserPoolId: AWS_USER_POOL_ID,
        ClientId:   AWS_CLIENT_ID,

        AuthParameters:{
            USERNAME: username,
            PASSWORD: password,
            SECRET_HASH: createSecretHash(username)
        },

        ContextData:{
            IpAddress:   req.ip,
            ServerName:  SERVER_NAME,
            ServerPath:  '/login',
            HttpHeaders: formatHeaders(req.headers)
        }
        
    }

    try{
        const result = await cognito.adminInitiateAuth(params).promise();
        res.json({message: 'Successfully logged in.', result})
    }
    catch(error){
        res.json({message:'An error occured logging in', error})
    }
})

app.post('/forgot-password', async (req, res) => {
    const {username} = req.body;

    const params = {
        ClientId: AWS_CLIENT_ID,
        Username: username,
        SecretHash: createSecretHash(username)
    }

    try{
        const result = await cognito.forgotPassword(params).promise();
        res.json({message:'Check your email for a confirmation code', result})
    }
    catch(error){
        res.json({error})
    }
})

app.post('/confirm-forgot-password', async (req, res) => {
    const {confirmationCode, username, password} = req.body;

    const params = {
        ClientId: AWS_CLIENT_ID,
        ConfirmationCode: confirmationCode,
        Username:username,
        Password:password,
        SecretHash: createSecretHash(username)
    }

    try{
        const result = await cognito.confirmForgotPassword(params).promise();
        res.json({message:'Your password has been reset.', result})
    }
    catch(error){
        res.json({error});
    }
})

app.post('/change-password', async (req, res) => {
    const {previousPassword, proposedPassword, accessToken} = req.body;
    const params = {
        AccessToken: accessToken,
        PreviousPassword: previousPassword,
        ProposedPassword: proposedPassword
    }

    try{
        const result = await cognito.changePassword(params).promise();
        res.json({message:'Your password has been changed', result})
    }
    catch(error){
        res.json({error});
    }
})

app.post('/delete-account', async (req, res) => {
    const params = {
        AccessToken:req.body.accessToken
    }

    try{
        const result = await cognito.deleteUser(params).promise();
        res.json({message:'Your account has been deleted', result})
    }
    catch(error){
        res.json({error});
    }
})

app.listen(3000, () => console.log('Listening on port 3000'));