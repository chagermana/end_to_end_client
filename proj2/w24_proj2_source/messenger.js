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

const MAX_SKIP = 1000 // most skipped message keys we will ever store

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
    // both pub and sec are genereated from generateEG but only the public key i share
    // the secret key always stays with this object
    this.EGKeyPair = await generateEG()

    // add our publick key
    const certificate = {
      username,
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

    // if valid then true else false
    const valid = await verifyWithECDSA(this.caPublicKey, certString, signature)

    // tampering deteccted then do not share the certificate and throw an error
    if (!valid) {
      throw 'certificate signature invalid, its possible the cert was tampered with'
    }
    // store it unchanged under the username, so sendmessage and receivemessage can use it to find the public key of the other user
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

  /**
   * Encrypt and send a message using Double Ratchet.
   *
   * Returns [header, ciphertext].
   */
  async sendMessage (name, plaintext) {
    // Initialize the session if this is our first message.
    const state = await this.startSession(name, true)

    // A sending chain must exist before encryption.
    if (!state.sendChainKey) {
      throw new Error('Sending chain is not initialized')
    }

    // Derive a fresh message key and the next chain key.
    const { messageKey, nextChainKey } =
      await this.advanceChain(state.sendChainKey)

    // Create fresh IVs for the recipient and government.
    const receiverIV = genRandomSalt()
    const ivGov = genRandomSalt()

    // Create a temporary ElGamal key pair for government encryption.
    const govEphemeral = await generateEG()

    // Derive a shared secret using the government's public key.
    const govSharedSecret = await computeDH(
      govEphemeral.sec,
      this.govPublicKey
    )

    // Convert the shared secret into an AES-GCM key.
    const govAESKey = await HMACtoAESKey(
      govSharedSecret,
      govEncryptionDataStr
    )

    // Export the message key as raw bytes for government encryption.
    // This is required by the assignment's surveillance mechanism.
    const rawMessageKey = await cryptoKeyToJSON(messageKey)

    // Convert the JWK's base64url-encoded key into raw bytes.
    const messageKeyBytes = Buffer.from(
      rawMessageKey.k,
      'base64url'
    )

    // Encrypt the message key for the government.
    const cGov = await encryptWithGCM(
      govAESKey,
      messageKeyBytes,
      ivGov
    )

    // Construct the authenticated message header.
    const header = {
      dh: state.DHs.pub,
      pn: state.PN,
      n: state.Ns,
      vGov: govEphemeral.pub,
      cGov,
      ivGov,
      receiverIV
    }

    // Authenticate the entire header with AES-GCM.
    const ciphertext = await encryptWithGCM(
      messageKey,
      plaintext,
      receiverIV,
      JSON.stringify(header)
    )

    // Discard the old sending chain key.
    state.sendChainKey = nextChainKey
    state.Ns += 1

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

  /**
   * Receive, authenticate and decrypt an encrypted message.
   *
   * Rejects tampered, repeated or out-of-order messages.
   */
    async receiveMessage (name, [header, ciphertext]) {
    // Ensure the sender has a verified certificate.
    if (!this.certs[name]) {
      throw new Error('Unknown sender: ' + name)
    }

    // Initialize the receiving session if necessary.
    const state = await this.startSession(name, false)

    // Validate required header information.
    if (!header || !header.dh ||
        !header.receiverIV || !header.vGov ||
        !header.cGov || !header.ivGov ||
        !Number.isSafeInteger(header.n) || header.n < 0 ||
        !Number.isSafeInteger(header.pn) || header.pn < 0) {
      throw new Error('Invalid message header')
    }

    const currentDH = state.DHr
      ? JSON.stringify(await cryptoKeyToJSON(state.DHr))
      : null
    const incomingDH = JSON.stringify(await cryptoKeyToJSON(header.dh))
    const headerString = JSON.stringify(header)

    // 1. Is this a message whose key we saved earlier?
    const savedId = incomingDH + ':' + header.n
    if (state.skipped[savedId]) {
      const savedPlaintext = await decryptWithGCM(
        state.skipped[savedId],
        ciphertext,
        header.receiverIV,
        headerString
      )
      // Delete the key only after the message authenticated.
      delete state.skipped[savedId]
      return bufferToString(savedPlaintext)
    }

    // 2. Work on copies, so a forged message cannot damage our real state.
    let rootKey = state.rootKey
    let recvChainKey = state.recvChainKey
    let Nr = state.Nr
    let DHs = state.DHs
    let sendChainKey = state.sendChainKey
    let PN = state.PN
    let Ns = state.Ns
    const newSkipped = {}

    // 3. Did the sender move to a new DH key?
    if (currentDH !== incomingDH) {
      if (state.DHr) {
        // The sender's old chain must be at least as long as what we received.
        if (header.pn < Nr) {
          throw new Error('Invalid message header')
        }
        // Save the keys of old-chain messages that have not arrived yet.
        const old = await this.skipMessageKeys(recvChainKey, Nr, header.pn)
        for (const s of old.skipped) {
          newSkipped[currentDH + ':' + s.n] = s.messageKey
        }
      }

      // DH ratchet step for receiving.
      const recv = await this.advanceDHRatchet(rootKey, DHs.sec, header.dh)
      rootKey = recv.rootKey
      recvChainKey = recv.chainKey
      Nr = 0

      // Start a fresh sending ratchet for our next reply.
      PN = Ns
      Ns = 0
      DHs = await generateEG()
      const send = await this.advanceDHRatchet(rootKey, DHs.sec, header.dh)
      rootKey = send.rootKey
      sendChainKey = send.chainKey
    }

    // 4. Skip ahead in the current chain, saving keys of skipped messages.
    if (header.n < Nr) {
      throw new Error('Repeated message')
    }
    if (!recvChainKey) {
      throw new Error('Receiving chain is not initialized')
    }
    const skip = await this.skipMessageKeys(recvChainKey, Nr, header.n)
    for (const s of skip.skipped) {
      newSkipped[incomingDH + ':' + s.n] = s.messageKey
    }

    // Never store more than MAX_SKIP keys in total.
    if (Object.keys(state.skipped).length +
        Object.keys(newSkipped).length > MAX_SKIP) {
      throw new Error('Too many skipped messages')
    }

    // 5. Derive this message's key and decrypt (this also checks the header).
    const { messageKey, nextChainKey } =
      await this.advanceChain(skip.chainKey)
    const plaintextBuffer = await decryptWithGCM(
      messageKey,
      ciphertext,
      header.receiverIV,
      headerString
    )

    // 6. Authenticated: now it is safe to commit everything to state.
    state.rootKey = rootKey
    state.DHs = DHs
    state.DHr = header.dh
    state.sendChainKey = sendChainKey
    state.PN = PN
    state.Ns = Ns
    state.recvChainKey = nextChainKey
    state.Nr = header.n + 1
    Object.assign(state.skipped, newSkipped)

    return bufferToString(plaintextBuffer)
  }

  // helper for sendMessage and receiveMessage;
  // Alice's secret with Bob's
  // public key equals Bob's secret with Alice's public key.
  async initialRootKey (name) {
    if (this.certs[name] === undefined) {
      throw 'certificate not found for' + name
    }
    // result is a hmac cryptokey, which is what hkdf expects as input
    return await computeDH(this.EGKeyPair.sec, this.certs[name].pub)
  }

  /**
   * Advance a symmetric chain by one message.
   *
   * The current chain key is used to derive a message key for this message,
   * and a new chain key for the next message.
   * Note that this function does not retain the current chain key,
   * so it is not possible to derive any previous message keys.
   *
   * @param {CryptoKey} chainKey - Current HMAC chain key
   * @returns {Promise<Object>} New message and chain keys
   */
  async advanceChain (chainKey) {
    if (!chainKey) {
      throw new Error('Chain key is not initialized')
    }

    // Derive an AES-GCM key for this message only.
    const messageKey = await HMACtoAESKey(
      chainKey,
      'message-key'
    )

    // Derive the next HMAC chain key.
    const nextChainKey = await HMACtoHMACKey(
      chainKey,
      'chain-key'
    )

    return {
      messageKey,
      nextChainKey
    }
  }

    /**
   * Move a receiving chain forward from message number `from` up to (not
   * including) `until`, saving the message key of each message we pass.
   * Changes no state: it returns the new chain key and the saved keys,
   * so the caller decides whether to keep them.
   */
  async skipMessageKeys (chainKey, from, until) {
    if (until - from > MAX_SKIP) {
      throw new Error('Too many skipped messages')
    }
    const skipped = []
    let current = chainKey
    for (let i = from; i < until; i++) {
      const { messageKey, nextChainKey } = await this.advanceChain(current)
      skipped.push({ n: i, messageKey })
      current = nextChainKey
    }
    return { chainKey: current, skipped }
  }

  /**
   * Perform a Diffie-Hellman ratchet derivation.
   *
   * Combines the current root key with a new DH secret
   * to produce an updated root key and a chain key.
   *
   * @param {CryptoKey} rootKey - Current root key
   * @param {CryptoKey} privateKey - Our DH private key
   * @param {CryptoKey} publicKey - Contact's DH public key
   * @returns {Promise<Object>} Updated root and chain keys
   */
  async advanceDHRatchet (rootKey, privateKey, publicKey) {
    // Compute a shared secret using Diffie-Hellman.
    const sharedSecret = await computeDH(
      privateKey,
      publicKey
    )

    // Derive two new keys from the shared secret
    // and the current root key.
    const [newRootKey, newChainKey] = await HKDF(
      sharedSecret,
      rootKey,
      'double-ratchet'
    )

    return {
      rootKey: newRootKey,
      chainKey: newChainKey
    }
  }

  /**
   * Initialize the Double Ratchet state for a contact.
   *
   * The first sender starts with a fresh DH ratchet key pair.
   * The first receiver initially uses their certificate key pair.
   *
   * @param {string} name - Contact's username
   * @param {boolean} isSender - Whether we initiate the session
   */
  async startSession (name, isSender) {
    if (!this.certs[name]) {
      throw new Error('No certificate found for ' + name)
    }

    // Each contact gets an independent session.
    if (this.conns[name]) {
      return this.conns[name]
    }

    // Person 1's helper establishes the shared initial root.
    const rootKey = await this.initialRootKey(name)

    const state = {
      rootKey,
      DHs: null, // Our current ratchet key pair
      DHr: null, // Contact's current ratchet public key
      sendChainKey: null,
      recvChainKey: null,
      Ns: 0, // Messages sent in current sending chain
      Nr: 0, // Messages received in current receiving chain
      PN: 0,
      skipped: {} // Length of previous sending chain
    }

    if (isSender) {
      // The initiating client creates a fresh ratchet key pair.
      state.DHs = await generateEG()
      state.DHr = this.certs[name].pub

      const result = await this.advanceDHRatchet(
        state.rootKey,
        state.DHs.sec,
        state.DHr
      )

      state.rootKey = result.rootKey
      state.sendChainKey = result.chainKey
    } else {
      // The receiving client initially uses its certificate keys.
      state.DHs = this.EGKeyPair
    }

    this.conns[name] = state
    return state
  }
};

module.exports = {
  MessengerClient
}
