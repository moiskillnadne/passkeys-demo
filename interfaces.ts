import { AuthenticatorTransportFuture, WebAuthnCredential } from "@simplewebauthn/server/script/deps"

export interface User {
  id: string
  email: string
}

export type Email = string;

export interface InMemoryDB {
  users: Record<Email, User>;
  userCredentials: Record<Email, WebAuthnCredential[]>;
  challenges: Record<Email, string>;
}