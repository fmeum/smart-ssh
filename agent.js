(function() {
  'use strict';

  const util = openpgp.util;
  const GSC = GoogleSmartCard;

  const AGENT_MESSAGE_TYPE = 'auth-agent@openssh.com';

  const SSH_AGENT_FAILURE = 5;
  const SSH_AGENT_SUCCESS = 6;

  const SSH2_AGENTC_REQUEST_IDENTITIES = 11;
  const SSH2_AGENTC_SIGN_REQUEST = 13;

  const SSH2_AGENT_IDENTITIES_ANSWER = 12;
  const SSH2_AGENT_SIGN_RESPONSE = 14;

  /**
   * Client title for the connection to the server App.
   *
   * Currently this is only used for the debug logs produced by the server App.
   */
  const CLIENT_TITLE = 'smart-ssh';

  /**
   * Identifier of the server App.
   */
  const SERVER_APP_ID = GSC.PcscLiteCommon.Constants.SERVER_OFFICIAL_APP_ID;


  let identityCache = {};

  async function fetchIdentities(manager) {
    identityCache = {};
    let readers;
    try {
      readers = await manager.listReaders();
    } catch (error) {
      console.log('Failed to list readers.');
      await smartCard.logError(error);
      return [];
    }
    return Promise.all(readers.map(async function(reader) {
        const asyncManager = new smartCard.OpenPGPSmartCardManager();
        await asyncManager.establishContext();
        try {
          await asyncManager.connect(reader);
        } catch (error) {
          console.log(`Failed to connect to reader ${reader}, skipping.`);
          await smartCard.logError(error);
          await asyncManager.releaseContext();
          return [];
        }
        let readerKeyBlob;
        let readerKeyId;
        try {
          await asyncManager.selectApplet();
          if (await asyncManager.fetchPinVerificationTriesRemaining() ===
            0) {
            await asyncManager.disconnect();
            return {};
          }
          readerKeyBlob = await asyncManager.fetchPublicKeyBlob();
          readerKeyId = await asyncManager.fetchAuthenticationPublicKeyId();
        } catch (error) {
          console.log(
            `Failed to get public key ID from reader ${reader}, skipping.`
          );
          await smartCard.logError(error);
          return [];
        } finally {
          await asyncManager.disconnect();
          await asyncManager.releaseContext();
        }
        identityCache[util.bin2str(readerKeyBlob)] = {
          reader,
          readerKeyId
        };
        return [readerKeyBlob];
      }))
      .then(identities => [].concat(...identities));
  }

  // TODO: exclude comment?
  // SSH agent protocol, Section 2.5.2 
  async function handleRequestIdentities() {
    await smartCard.initializeApiContext();
    const manager = new smartCard.OpenPGPSmartCardManager();
    await manager.establishContext();
    const identities = await fetchIdentities(manager);
    await manager.releaseContext();
    const header = util.concatUint8Array([
      new Uint8Array([SSH2_AGENT_IDENTITIES_ANSWER]),
      util.writeNumber(identities.length, 4)
    ]);
    const body = util.concatUint8Array(identities.map(identity =>
      util.concatUint8Array([
        util.writeNumber(identity.length, 4),
        identity,
        util.writeNumber(0, 4)
        //util.writeNumber(identity.reader.length, 4),
        //new Uint8Array(util.str2bin(identity.reader))
      ])
    ));
    return Array.from(util.concatUint8Array([header, body]));
  }

  async function requestAndVerifyPin(manager, fingerprint) {
    let pin = pinCache.getPin(fingerprint, manager.reader);
    let cachePin = false;
    // TODO: try
    let dialogData = {
      fingerprint,
      reader: manager.readerShort,
      triesRemaining: await manager.fetchPinVerificationTriesRemaining(),
    }
    if (!pin) {
      const pinDialogPromise = new Promise(function(resolve) {
        dialogData.resolvePromise = (pin, cachePin) => resolve([pin,
          cachePin
        ]);
      });
      chrome.app.window.create('pinDialog.html', {
          id: 'pinDialog',
          innerBounds: {
            minWidth: 230,
            maxWidth: 230,
            minHeight: 100,
            maxHeight: 100
          },
          alwaysOnTop: true,
          frame: 'none',
          resizable: false,
          visibleOnAllWorkspaces: true
        },
        createdWindow => createdWindow.contentWindow.data = dialogData
      );
      // Wait for user to enter PIN
      [pin, cachePin] = await pinDialogPromise;
    }
    const pinBytes = util.str2Uint8Array(util.encode_utf8(pin));
    // Verify PIN for authentication
    try {
      await manager.transmit(new smartCard.CommandAPDU(0x00, 0x20, 0x00, 0x82,
        pinBytes));
      // At this point PIN verification has succeeded
      if (cachePin)
        pinCache.putPin(fingerprint, manager.reader, pin);
    } catch (error) {
      if (util.isUint8Array(error) && error.length === 2) {
        // Special status bytes
        switch (util.readNumber(error)) {
          // Invalid PIN, ask again
          case 0x6982:
            // Delete the (invalid) PIN if cached
            // This should only ever happen if the user changes the PIN while it
            // is still cached. Requires a very fast user.
            if (cachePin)
              pinCache.deletePin(fingerprint, manager.reader);
            await requestAndVerifyPin(manager);
            break;
            // Device is blocked (this should not be reached as we check the
            // number of remaining tries and block PIN entry in this case)
          case 0x6983:
            throw Error('Device is blocked.');
          default:
            throw error;
        }
      } else {
        // pcsclite error
        throw error;
      }
    }
  }

  const HashAlgorithms = {
    SHA1: {
      algorithmNumber: 2,
      inputLength: 35,
      signaturePrefix: 'ssh-rsa',
    },
    SHA256: {
      algorithmNumber: 8,
      inputLength: 51,
      signaturePrefix: 'rsa-sha2-256',
    },
    SHA512: {
      algorithmNumber: 10,
      inputLength: 83,
      signaturePrefix: 'rsa-sha2-512',
    },
  };

  async function authenticateOnSmartCard(
      manager, reader, readerKeyId, data, hashAlgo) {
    try {
      await manager.connect(reader);
    } catch (error) {
      console.log(`Failed to connect to reader ${reader}.`);
      await smartCard.logError(error);
      return;
    }
    let currentReaderKeyId;
    try {
      currentReaderKeyId = await manager.fetchAuthenticationPublicKeyId();
    } catch (error) {
      console.log(`Failed to fetch public key ID from reader ${reader}.`);
      await smartCard.logError(error);
      await manager.disconnect();
      return;
    }
    if (!util.equalsUint8Array(readerKeyId, currentReaderKeyId)) {
      console.log(`Public key ID changed for ${reader}.`);
      await manager.disconnect();
      return;
    }
    const fingerprint = util.hexidump(readerKeyId.slice(4)).toUpperCase();
    try {
      await requestAndVerifyPin(manager, fingerprint);
    } catch (error) {
      console.log('PIN verification failed.');
      await smartCard.logError(error);
      await manager.disconnect();
      return;
    }
    let modulusLength;
    try {
      modulusLength = await manager.fetchAuthenticationModulusLengthBytes();
    } catch (error) {
      console.log(`Failed to fetch key modulus length from reader ${reader}.`);
      await smartCard.logError(error);
      await manager.disconnect();
      return;
    }
    const pkcsEncodedMessage = new Uint8Array(
        openpgp.crypto.pkcs1.emsa.encode(hashAlgo.algorithmNumber,
            util.bin2str(data), modulusLength)
      .toByteArray());
    const authenticationInput = pkcsEncodedMessage.slice(-hashAlgo.inputLength);
    let signature;
    try {
      signature = await manager.transmit(new smartCard.CommandAPDU(0x00, 0x88,
        0x00, 0x00, authenticationInput));
    } catch (error) {
      console.log('Internal authenticate failed.');
      await smartCard.logError(error);
      await manager.disconnect();
      return;
    }
    await manager.disconnect();
    return signature;
  }

  // SSH agent protocol, Section 2.6.2
  async function handleSignRequest(body) {
    const keyBlobLength = util.readNumber(body.slice(0, 4));
    const keyBlob = body.slice(4, 4 + keyBlobLength);
    const dataLength = util.readNumber(body.slice(4 + keyBlobLength, 4 +
      keyBlobLength + 4));
    if (4 + keyBlobLength + 4 + dataLength !== body.length - 4) {
      console.log('SSH2_AGENTC_SIGN_REQUEST: Invalid length fields');
      return [SSH_AGENT_FAILURE];
    }
    const data = body.slice(4 + keyBlobLength + 4, 4 + keyBlobLength + 4 +
      dataLength);
    const flags = util.readNumber(body.slice(body.length - 4));
    let hashAlgo;
    if (flags === 0) {
      hashAlgo = HashAlgorithms.SHA1;
    } else if (flags & 0b100) {
      hashAlgo = HashAlgorithms.SHA512;
    } else if (flags & 0b10) {
      hashAlgo = HashAlgorithms.SHA256;
    } else {
      console.log('SSH2_AGENTC_SIGN_REQUEST: unsupported flags');
      return [SSH_AGENT_FAILURE];
    }
    const keyBlobStr = util.bin2str(keyBlob);
    if (!(keyBlobStr in identityCache)) {
      console.log('SSH2_AGENTC_SIGN_REQUEST: Invalid key blob/requested');
      return [SSH_AGENT_FAILURE];
    }
    const {
      reader,
      readerKeyId
    } = identityCache[keyBlobStr];
    await smartCard.initializeApiContext();
    const manager = new smartCard.OpenPGPSmartCardManager();
    await manager.establishContext();
    const signature = await authenticateOnSmartCard(manager, reader,
        readerKeyId, data, hashAlgo);
    await manager.releaseContext();
    if (!signature)
      return [SSH_AGENT_FAILURE];
    const response = util.concatUint8Array([
      new Uint8Array([SSH2_AGENT_SIGN_RESPONSE]),
      util.writeNumber(4 + hashAlgo.signaturePrefix.length + 4 +
          signature.length, 4),
      util.writeNumber(hashAlgo.signaturePrefix.length, 4),
      new Uint8Array(util.str2bin(hashAlgo.signaturePrefix)),
      util.writeNumber(signature.length, 4),
      signature
    ]);
    return Array.from(response);
  }

  async function agent(request, port) {
    if (request.type !== AGENT_MESSAGE_TYPE)
      return;

    let responseData;
    switch (request.data[0]) {
      // Ping
      case 0:
        try {
          await smartCard.initializeApiContext();
          responseData = [SSH_AGENT_SUCCESS];
        } catch (error) {
          console.log(error);
          responseData = [SSH_AGENT_FAILURE];
        }
        break;
      case SSH2_AGENTC_REQUEST_IDENTITIES:
        try {
          responseData = await handleRequestIdentities();
        } catch (error) {
          console.log(error);
          responseData = [SSH_AGENT_FAILURE];
        }
        break;
      case SSH2_AGENTC_SIGN_REQUEST:
        try {
          responseData = await handleSignRequest(request.data.slice(1));
        } catch (error) {
          console.log(error);
          responseData = [SSH_AGENT_FAILURE];
        }
        break;
      default:
        console.log('Unsupported request:', request.data);
        responseData = [SSH_AGENT_FAILURE];
    }
    port.postMessage({
      type: AGENT_MESSAGE_TYPE,
      data: responseData
    });
  }

  chrome.runtime.onConnectExternal.addListener(function(port) {
    port.onMessage.addListener(agent);
  });
  chrome.runtime.onSuspend.addListener(function() {
    console.log('agent unloaded');
  });
  chrome.app.runtime.onLaunched.addListener(function() {
    chrome.app.window.create('app.html', {
      id: 'app',
      innerBounds: {
        minWidth: 900,
        maxWidth: 900,
        minHeight: 500
      },
      resizable: true,
    });
  });
})();
