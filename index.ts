import crypto from 'crypto'
import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import swaggerUI from 'swagger-ui-express';
import swaggerJSDocs from 'swagger-jsdoc'

import { Email, InMemoryDB, User } from './interfaces';

dotenv.config();

import {
  // Authentication
  generateAuthenticationOptions,
  // Registration
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';

import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from '@simplewebauthn/types';


const app = express();

const {
  PORT = null,
  RP_ID = null,
  EXPECTED_ORIGIN = null,
} = process.env;

if(PORT === null) {
  throw new Error('PORT is required');
}

if(RP_ID === null) {
  throw new Error('RP_ID is required');
}

if(EXPECTED_ORIGIN === null) {
  throw new Error('EXPECTED_ORIGIN is required');
}

const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'Webauthn Demo API',
      version: '1.0.0',
      description: 'Webauthn / Passkeys',
    },
    servers: [
      {
        url: EXPECTED_ORIGIN, // URL сервера
      },
    ],
  },
  apis: ['./index.*'], // Путь к файлам с описанием эндпоинтов
};

const swaggerDocs = swaggerJSDocs(swaggerOptions);

app.use(express.json());

app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDocs));

export const rpID = RP_ID;
export const expectedOrigin = EXPECTED_ORIGIN


const inMemoryDB: InMemoryDB = {
  users: {},
  userCredentials: {},
  challenges: {},
}

/**
 * @swagger
 * /api/healthcheck:
 *   get:
 *     summary: Healthcheck endpoint
 *     description: Endpoint to check the health of the server
 *     responses:
 *       200:
 *         description: OK
 */
app.get('/api/healthcheck', (req, res) => {
  res.status(200).send('OK');
})

/**
 * @swagger
 * /api/debug/inMemoryDB:
 *   get:
 *     summary: Get the in-memory database
 *     description: Returns the in-memory database used by the server
 *     responses:
 *       200:
 *         description: The in-memory database
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 users:
 *                   type: object
 *                   description: The users in the database
 *                 userCredentials:
 *                   type: object
 *                   description: The user credentials in the database
 *                 challenges:
 *                   type: object
 *                   description: The challenges in the database
 */
app.get('/api/debug/inMemoryDB', (req, res) => {
  res.status(200).send(inMemoryDB);
})

/**
 * @swagger
 * /api/signup:
 *   post:
 *     summary: Register a new user
 *     description: Creates a new user with a unique identifier based on the provided email.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The email of the new user
 *     responses:
 *       200:
 *         description: User successfully registered
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Operation status
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       description: The unique identifier of the user
 *                     email:
 *                       type: string
 *                       description: The email of the registered user
 *       400:
 *         description: Registration error if the email is not provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 */
app.post('/api/signup', async (req: Request, res: Response): Promise<any> => {
  const { email } = req.body as { email: Email };

  if(!email) {
    return res.status(400).send({ error: 'Email is required' });
  }

  const user: User = {
    id: crypto.randomUUID(),
    email
  }

  inMemoryDB.users[email] = user;

  res.status(200).send({
    success: true,
    user
  });
})

/**
 * @swagger
 * /api/generate-registration-options:
 *   get:
 *     summary: Generate WebAuthn registration options for a user
 *     description: Generates registration options for WebAuthn for an existing user, based on their email. This endpoint provides options to begin the WebAuthn registration process.
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *           format: email
 *         description: The email of the user to generate WebAuthn registration options for.
 *     responses:
 *       200:
 *         description: WebAuthn registration options successfully generated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 rpName:
 *                   type: string
 *                   description: The relying party name
 *                 rpID:
 *                   type: string
 *                   description: The relying party ID
 *                 userName:
 *                   type: string
 *                   description: The user's email
 *                 timeout:
 *                   type: integer
 *                   description: Timeout in milliseconds
 *                 attestationType:
 *                   type: string
 *                   description: Attestation type
 *                 excludeCredentials:
 *                   type: array
 *                   description: List of credentials to exclude from registration
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                         description: Credential ID
 *                       type:
 *                         type: string
 *                         description: Credential type, typically "public-key"
 *                       transports:
 *                         type: array
 *                         items:
 *                           type: string
 *                         description: Authenticator transports supported by the credential
 *                 authenticatorSelection:
 *                   type: object
 *                   description: Criteria for authenticator selection
 *                   properties:
 *                     residentKey:
 *                       type: string
 *                       description: Resident key requirement
 *                     userVerification:
 *                       type: string
 *                       description: User verification requirement
 *                 supportedAlgorithmIDs:
 *                   type: array
 *                   description: Supported algorithms
 *                   items:
 *                     type: integer
 *       400:
 *         description: Error if email is not provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message indicating that the email is required
 *       404:
 *         description: Error if user not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message indicating that the user by email was not found
 */
app.get('/api/generate-registration-options', async (req, res): Promise<any> => {
  const email = req.query.email as Email;

  if(!email) {
    return res.status(400).send({ error: 'Email is required' });
  }

  const user = inMemoryDB.users[email];

  if(!user) {
    return res.status(404).send({ error: 'User by email not found. Please register a user.' });
  }

  const credentials = inMemoryDB.userCredentials[email] || [];

  const opts: GenerateRegistrationOptionsOpts = {
    rpName: 'SimpleWebAuthn Example',
    rpID,
    userName: user.email,
    timeout: 60000,
    attestationType: 'none',
    excludeCredentials: credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'discouraged',
      userVerification: 'preferred',
    },
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = await generateRegistrationOptions(opts);

  inMemoryDB.challenges[email] = options.challenge;

  res.status(200).send(options);
});

/**
 * @swagger
 * /api/verify-registration:
 *   post:
 *     summary: Verify WebAuthn registration response
 *     description: Verifies the WebAuthn registration response for a user based on their email and stores the credentials if verification is successful.
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *           format: email
 *         description: The email of the user to verify WebAuthn registration for.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               response:
 *                 type: object
 *                 description: The WebAuthn registration response from the client.
 *               transports:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: The authenticator transports supported by the credential.
 *     responses:
 *       200:
 *         description: WebAuthn registration response successfully verified
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates whether the registration verification was successful.
 *                 verified:
 *                   type: boolean
 *                   description: Indicates if the WebAuthn response was verified.
 *       400:
 *         description: Error if the email is missing or the registration response is invalid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message explaining why the request failed.
 *       404:
 *         description: Error if the user with the provided email is not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message indicating that the user with the provided email was not found.
 */
app.post('/api/verify-registration', async (req, res): Promise<any> => {
  const email = req.query.email as Email;

  if(!email) {
    return res.status(400).send({ error: 'Email is required' });
  }

  const user = inMemoryDB.users[email];

  if(!user) {
    return res.status(404).send({ error: 'User by email not found. Please register a user.' });
  }

  const body: RegistrationResponseJSON = req.body;

  const expectedChallenge = inMemoryDB.challenges[email];

  let verification: VerifiedRegistrationResponse;
  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: false,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credential } = registrationInfo;

    const existingCredential = inMemoryDB.userCredentials[email]?.find((cred) => cred.id === credential.id);

    if (!existingCredential) {
      /**
       * Add the returned credential to the user's list of credentials
       */
      const newCredential: WebAuthnCredential = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: body.response.transports,
      };
      inMemoryDB.userCredentials[email].push(newCredential);
    }
  }

  delete inMemoryDB.challenges[email]

  res.status(200).send({ success: true, verified });
});

/**
 * @swagger
 * /api/generate-authentication-options:
 *   get:
 *     summary: Generate WebAuthn authentication options for a user
 *     description: Generates WebAuthn authentication options for an existing user based on their email, providing the necessary information for starting the authentication process.
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *           format: email
 *         description: The email of the user to generate WebAuthn authentication options for.
 *     responses:
 *       200:
 *         description: WebAuthn authentication options successfully generated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 timeout:
 *                   type: integer
 *                   description: Timeout in milliseconds for the authentication options
 *                 allowCredentials:
 *                   type: array
 *                   description: List of credentials allowed for authentication
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                         description: Credential ID
 *                       type:
 *                         type: string
 *                         description: Credential type, typically "public-key"
 *                       transports:
 *                         type: array
 *                         items:
 *                           type: string
 *                         description: Authenticator transports supported by the credential
 *                 userVerification:
 *                   type: string
 *                   description: The user verification requirement (e.g., "preferred", "required")
 *                 rpID:
 *                   type: string
 *                   description: The relying party ID
 *                 challenge:
 *                   type: string
 *                   description: The challenge for the WebAuthn authentication
 *       400:
 *         description: Error if email is not provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message indicating that the email is required
 *       404:
 *         description: Error if user is not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message indicating that the user with the provided email was not found
 */
app.get('/api/generate-authentication-options', async (req, res): Promise<any> => {
  const email = req.query.email as Email;

  if(!email) {
    return res.status(400).send({ error: 'Email is required' });
  }

  const user = inMemoryDB.users[email];

  if(!user) {
    return res.status(404).send({ error: 'User by email not found. Please register a user.' });
  }

  const userCredentials = inMemoryDB.userCredentials[email] || [];

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: userCredentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
    userVerification: 'preferred',
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);

  inMemoryDB.challenges[email] = options.challenge;

  res.status(200).send(options);
});


/**
 * @swagger
 * /api/verify-authentication:
 *   post:
 *     summary: Verify WebAuthn authentication response
 *     description: Verifies the WebAuthn authentication response for a user based on their email and updates the credential's counter if the verification is successful.
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *           format: email
 *         description: The email of the user to verify WebAuthn authentication for.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id:
 *                 type: string
 *                 description: The credential ID of the user.
 *               response:
 *                 type: object
 *                 description: The WebAuthn authentication response from the client.
 *     responses:
 *       200:
 *         description: WebAuthn authentication response successfully verified
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates whether the authentication verification was successful.
 *                 verified:
 *                   type: boolean
 *                   description: Indicates if the WebAuthn response was verified.
 *       400:
 *         description: Error if the email is missing, the authenticator is not registered, or the authentication response is invalid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message explaining why the request failed.
 *       404:
 *         description: Error if the user with the provided email is not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message indicating that the user with the provided email was not found.
 */
app.post('/api/verify-authentication', async (req, res): Promise<any> => {
  const email = req.query.email as Email;

  if(!email) {
    return res.status(400).send({ error: 'Email is required' });
  }

  const user = inMemoryDB.users[email];

  if(!user) {
    return res.status(404).send({ error: 'User by email not found. Please register a user.' });
  }


  const body: AuthenticationResponseJSON = req.body;


  const expectedChallenge = inMemoryDB.challenges[email];

  const dbCredential: WebAuthnCredential | undefined = inMemoryDB.userCredentials[email]?.find((cred) => cred.id === body.id);

  if (!dbCredential) {
    return res.status(400).send({
      error: 'Authenticator is not registered with this site',
    });
  }

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      credential: dbCredential,
      requireUserVerification: false,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    dbCredential.counter = authenticationInfo.newCounter;
  }

  console.log('Updated credentials after login', inMemoryDB.userCredentials[email]);

  delete inMemoryDB.challenges[email];

  res.status(200).send({ success: true, verified });
});

app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
  console.log(`Swagger started on http://localhost:${PORT}/api-docs`);

  console.log(`Expected ORIGIN: ${EXPECTED_ORIGIN}`);
})