'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */

  /** 
  long term-ElGamal key pair is made
  returns a certificate that holds the public half. it is signed and other users use it ro find our public key 
  **/
  async generateCertificate (username) {

    //both pub and sec are genereated from generateEG but only the public key i share
    //the secret key always stays with this object
    this.EGKeyPair = await generateEG()

    //add our publick key
    const certificate ={
      username: username,
      pub: this.EGKeyPair.pub
    }
    return certificate

  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */

  /** 
  check another users certificate and stores is so that we can messahe them
  verification is done so that we know the certificate is valid and not tampered with
  **/
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)

    //if valid then true else false
    const valid = await verifyWithECDSA(this.caPublicKey, certString, signature)

    //tampering deteccted then do not share the certificate and throw an error
    if (!valid) {
      throw 'certificate signature invalid, its possible the cert was tampered with'
    }
    //store it unchanged under the username, so sendmessage and receivemessage can use it to find the public key of the other user
    this.certs[certificate.username] = certificate
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage (name, plaintext) {
    throw ('not implemented!')
    const header = {}
    const ciphertext = ''
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    throw ('not implemented!')
    return plaintext
  }

  //helper for sendMessage and receiveMessage; 
  //Alice's secret with Bob's
  //public key equals Bob's secret with Alice's public key.
  async initialRootKey (name) {
    if (this.certs[name] ===  undefined) {
      throw 'certificate not found for' + name
    }
    //result is a hmac cryptokey, which is what hkdf expects as input
    return await computeDH(this.EGKeyPair.sec, this.certs[name].pub)
  }
};

module.exports = {
  MessengerClient
}
