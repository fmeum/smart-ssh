const smartCard = (function() {
  'use strict';

  const util = openpgp.util;

  const GSC = GoogleSmartCard;
  const Constants = GSC.PcscLiteCommon.Constants;
  const API = GSC.PcscLiteClient.API;

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

  /**
   * Context for using the PC/SC-Lite client API.
   *
   * This object establishes and manages a connection to the server App. Upon
   * successful connection, a GoogleSmartCard.PcscLiteClient.API object is
   * returned through the callback, that allows to perform PC/SC-Lite client API
   * requests.
   * @type {GSC.PcscLiteClient.Context}
   */
  let apiContext = null;
  let api = null;

  function apiContextDisposedListener() {
    console.log('smartCard: API context disposed');
    apiContext = null;
  }

  async function initializeApiContext() {
    if (!apiContext || !api) {
      apiContext = new GSC.PcscLiteClient.Context(CLIENT_TITLE,
        SERVER_APP_ID);
      // Wait for an API context for at most 0.5 seconds
      api = await Promise.race([
        new Promise(function(resolve) {
          apiContext.addOnInitializedCallback(resolve);
          apiContext.addOnDisposeCallback(apiContextDisposedListener);
          apiContext.initialize();
        }),
        new Promise(resolve => setTimeout(resolve, 500))
      ]);
    }
    if (!apiContext || !api)
      throw Error(
        'Smart Card Connector extension not installed or disabled.');
  }

  async function logError(error) {
    // Numeric error codes signify PC/SC-Lite errors
    if (typeof error === 'number') {
      console.log('failed: PC/SC-Lite error: ' + error);
      try {
        const errorText = await api.pcsc_stringify_error(error);
        console.log('PC/SC-Lite error text: ' + errorText);
      } catch (e) {
        console.log(e);
      }
    } else {
      console.log(error);
    }
  }

  class OpenPGPSmartCardManager {
    constructor() {
      this.connected = false;
      this.context = 0;
      this.reader = null;
      this.cardHandle = 0;
      this.activeProtocol = 0;
      this.appletSelected = false;
    }

    get readerShort() {
      if (this.reader.includes('Yubikey NEO-N'))
        return 'Yubikey NEO-N';
      else if (this.reader.includes('Yubikey NEO'))
        return 'YubiKey NEO';
      else if (this.reader.includes('Yubikey 4'))
        return 'YubiKey 4';
      else
        return this.reader;
    }

    async establishContext() {
      if (!(await this.isValidContext())) {
        this.context = await this._execute(api.SCardEstablishContext(
          API.SCARD_SCOPE_SYSTEM, null, null));
      }
    }

    async isValidContext() {
      try {
        await this._execute(api.SCardIsValidContext(this.context));
      } catch (_) {
        return false;
      }
      return true;
    }

    async listReaders() {
      if ((await this.isValidContext()) && !this.connected) {
        return this._execute(api.SCardListReaders(this.context, null));
      }
    }

    async connect(reader) {
      if ((await this.isValidContext()) && !this.connected) {
        this.reader = reader;
        [this.cardHandle, this.activeProtocol] = await this._execute(api
          .SCardConnect(this.context,
            this.reader,
            API.SCARD_SHARE_EXCLUSIVE,
            API.SCARD_PROTOCOL_T1));
        this.connected = true;
      }
    }

    _execute(sCardPromise) {
      return sCardPromise.then(result => new Promise(
        function(resolve, reject) {
          result.get((...args) => args.length > 1 ? resolve(args) :
            resolve(
              args[0]), reject);
        }));
    }

    async _getData(result) {
      result[1] = new Uint8Array(result[1]);
      let data = result[1].slice(0, -2);
      const returnCode = result[1].slice(-2);
      if (returnCode[0] === 0x61) {
        const dataContinued = await this.transmit(new CommandAPDU(0x00,
          0xC0, 0x00, 0x00));
        data = util.concatUint8Array([data, dataContinued]);
      } else if (!(returnCode[0] === 0x90 && returnCode[1] === 0x00)) {
        console.log('Operation returned specific status bytes:',
          returnCode);
        throw returnCode;
      }
      return data;
    }

    async transmit(commandAPDU) {
      if (this.connected) {
        let data = null;
        for (const command of commandAPDU.commands) {
          const result = await this._execute(api.SCardTransmit(this.cardHandle,
            API.SCARD_PCI_T1, Array.from(command)));
          data = await this._getData(result);
        }
        return data;
      }
    }

    async selectApplet() {
      if (this.connected && !this.appletSelected) {
        await this.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, new Uint8Array(
          [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])));
        this.appletSelected = true;
      }
    }

    async disconnect() {
      if (this.connected) {
        await this._execute(api.SCardDisconnect(this.cardHandle, API.SCARD_LEAVE_CARD));
        this.appletSelected = false;
        this.connected = false;
        this.reader = null;
        this.cardHandle = 0;
        this.activeProtocol = 0;
      }
    }

    async releaseContext() {
      if (!(await this.isValidContext()))
        return;
      if (this.connected)
        await this.disconnect();
      await this._execute(api.SCardReleaseContext(this.context));
      this.context = 0;
    }

    async callOnDisconnect(readerName, callback) {
      if (!await this.isValidContext()) {
        callback();
      } else {
        // Returns immediately
        let readerState = await this._execute(api.SCardGetStatusChange(
          this.context,
          API.INFINITE, [API.createSCardReaderStateIn(
            readerName, API.SCARD_STATE_UNAWARE, 0x1)]));
        readerState[0].current_state = readerState[0].event_state;

        while (readerState[0].current_state & API.SCARD_STATE_PRESENT) {
          try {
            const newState = await this._execute(api.SCardGetStatusChange(
              this.context,
              API.INFINITE, [API.createSCardReaderStateIn(
                readerName, readerState[0].current_state, 0x1)]));
            readerState[0].current_state = newState[0].event_state;
          } catch (error) {
            if (error == API.SCARD_E_CANCELLED)
              return;
            if (error != API.SCARD_E_TIMEOUT) {
              callback();
              throw error;
            }
          }
        }
        callback();
      }
    }

    async callOnReaderEvent(callback) {
      if (!await this.isValidContext()) {
        throw Error('smartCard.callOnReaderEvent: Invalid context');
      } else {
        await this._execute(api.SCardGetStatusChange(
          this.context,
          API.INFINITE, [API.createSCardReaderStateIn(
            '\\\\?PnP?\\Notification', API.SCARD_STATE_UNAWARE, 0x1
          )]));
        callback();
      }
    }

    async cancelListeners() {
      await this._execute(api.SCardCancel(this.context));
    }

    // See RFC 4253, Section 6.6 and RFC 4251, Section 5
    async fetchPublicKeyBlob() {
      const publicKeyTemplate = DataObject.fromBytes(await this.transmit(
        new CommandAPDU(0x00, 0x47, 0x81, 0x00, new Uint8Array([0xA4,
          0x00
        ]))));
      let modulus = publicKeyTemplate.lookup(0x81);
      if (modulus[0] & (1 << 7))
        modulus = util.concatUint8Array([new Uint8Array([0]), modulus]);
      const exponent = publicKeyTemplate.lookup(0x82);
      return util.concatUint8Array([
        util.writeNumber(7, 4),
        new Uint8Array(util.str2bin('ssh-rsa')),
        util.writeNumber(exponent.length, 4),
        exponent,
        util.writeNumber(modulus.length, 4),
        modulus
      ]);
    }

    async fetchPublicKeyBlobBase64() {
      return btoa(String.fromCharCode.apply(
        null, await this.fetchPublicKeyBlob()));
    }

    async fetchAuthenticationPublicKeyId() {
      const appRelatedData = DataObject.fromBytes(await this.transmit(
        new CommandAPDU(0x00, 0xCA, 0x00, 0x6E)));
      return appRelatedData.lookup(0xC5).subarray(52, 60);
    }

    async fetchAuthenticationPublicKeyIdString() {
      return util.hexidump((await this.fetchAuthenticationPublicKeyId())
        .slice(4)).toUpperCase();
    }

    async fetchAuthenticationModulusLengthBytes() {
      const appRelatedData = DataObject.fromBytes(await this.transmit(
        new CommandAPDU(0x00, 0xCA, 0x00, 0x6E)));
      return util.readNumber(appRelatedData.lookup(0xC3).subarray(1, 3)) /
        8;
    }

    async fetchPinVerificationTriesRemaining() {
      const appRelatedData = DataObject.fromBytes(await this.transmit(
        new CommandAPDU(0x00, 0xCA, 0x00, 0x6E)));
      return appRelatedData.lookup(0xC4)[4];
    }
  }

  class CommandAPDU {
    constructor(cla, ins, p1, p2, data) {
      this.commands = [];

      if (!data) {
        this.commands.push(new Uint8Array([cla, ins, p1, p2, 0x00]));
        return;
      }

      let remainingBytes = data.length;

      while (remainingBytes > 0xFF) {
        const header = new Uint8Array([cla | 1 << 4, ins, p1, p2, 0xFF]);
        const body = data.subarray(data.length - remainingBytes, data.length -
          remainingBytes + 0xFF);
        const footer = new Uint8Array([0x00]);
        this.commands.push(util.concatUint8Array([header, body, footer]));
        remainingBytes -= 0xFF;
      }

      const header = new Uint8Array([cla, ins, p1, p2, remainingBytes]);
      const body = data.subarray(data.length - remainingBytes, data.length);
      const footer = new Uint8Array([0x00]);
      this.commands.push(util.concatUint8Array([header, body, footer]));
    }
  }

  const DATA_OBJECT_TAG = {
    0x5E: 'Login data',
    0x5F50: 'URL to public keys',

    0x65: 'Cardholder Related Data',
    0x5B: 'Name',
    0x5F2D: 'Language preference',
    0x5F35: 'Sex',

    0x6E: 'Application Related Data',
    0x4F: 'Application Identifier',
    0x5F52: 'Historical bytes',
    0x73: 'Discretionary data objects',
    0xC0: 'Extended capabilities',
    0xC1: 'Algorithm attributes: signature',
    0xC2: 'Algorithm attributes: decryption',
    0xC3: 'Algorithm attributes: authentication',
    0xC4: 'PW Status Bytes',
    0xC5: 'Fingerprints',
    0xC6: 'CA Fingerprints',
    0xCD: 'Generation Timestamps',

    0x7A: 'Security support template',
    0x93: 'Digital signature counter',

    0x7F49: 'Public key template',
    0x81: 'Modulus',
    0x82: 'Public exponent'
  };

  const DATA_OBJECT_TAG_CLASS = {
    0: 'universal',
    1: 'application',
    2: 'context-specific',
    3: 'private'
  };

  class DataObject {

    lookup(tag) {
      if (this.tag === tag)
        if (this.isConstructed)
          return this.children;
        else
          return this.value;
      else {
        if (this.isConstructed) {
          for (let child of this.children) {
            let result = child.lookup(tag);
            if (result !== null)
              return result;
          }
        }
        return null;
      }
    }

    static fromBytesWithStart(bytes, start) {
      let pos = start;
      if (pos < bytes.length) {
        const dataObject = new DataObject();
        const tagByte = bytes[pos++];
        dataObject.tagClass = tagByte >>> 6;
        dataObject.tagClassDescription = DATA_OBJECT_TAG_CLASS[dataObject
          .tagClass];
        const isConstructed = !!(tagByte & (1 << 5));
        dataObject.isConstructed = isConstructed;

        let tagNumber = tagByte & 0b00011111;
        let numTagNumberBytes = 1;
        if (tagNumber === 0b00011111) {
          if (!(bytes[pos] & 0b01111111))
            throw Error('First byte of the tag number is 0');
          tagNumber = 0;
          do {
            tagNumber = (tagNumber << 7) + bytes[pos] & 0b01111111;
            ++numTagNumberBytes;
          } while (bytes[pos++] & (1 << 7));
        }
        dataObject.tagNumber = tagNumber;
        dataObject.tag = util.readNumber(bytes.slice(pos -
          numTagNumberBytes, pos));
        dataObject.tagDescription = DATA_OBJECT_TAG[dataObject.tag] ||
          `<unimplemented tag: ${dataObject.tag}>`;

        const lengthByte = bytes[pos++];
        let valueLength = 0;
        if (lengthByte <= 0x7F) {
          valueLength = lengthByte;
        } else {
          const numLengthBytes = lengthByte & 0b01111111;
          for (let i = 0; i < numLengthBytes; ++i) {
            valueLength = (valueLength * 0x100) + bytes[pos++];
          }
        }
        dataObject.valueLength = valueLength;

        const valueStart = pos;
        const valueEnd = pos + valueLength;
        const value = bytes.slice(valueStart, valueEnd);

        if (isConstructed) {
          dataObject.children = [];
          while (pos < valueEnd) {
            // Skip zero bytes inbetween tags
            if (!bytes[pos]) {
              ++pos;
              continue;
            }
            let child;
            [child, pos] = DataObject.fromBytesWithStart(bytes, pos);
            dataObject.children.push(child);
          }
        } else {
          dataObject.value = value;
        }
        return [dataObject, valueEnd];
      } else {
        return [null, start];
      }
    }

    static fromBytes(bytes) {
      return DataObject.fromBytesWithStart(bytes, 0)[0];
    }
  }

  chrome.runtime.onSuspend.addListener(function() {
    console.log('smartCard: unloaded');
    console.log(new Error().stack);
  });

  initializeApiContext();

  return {
    OpenPGPSmartCardManager,
    CommandAPDU,
    DataObject,
    initializeApiContext,
    logError
  }
})();
