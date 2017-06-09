Secure Shell - OpenPGP smart card support (smart-ssh)
=========

smart-ssh is a Chrome app that acts as an ssh-agent for the [Secure Shell](https://chrome.google.com/webstore/detail/secure-shell/pnhechapfaindjhompbnflcldabbghjo) and supports SSH public key authentication using OpenPGP-enabled smart cards.

## Requirements
  You will need:
  * the [Secure Shell](https://chrome.google.com/webstore/detail/secure-shell/pnhechapfaindjhompbnflcldabbghjo) app.
  * an OpenPGP-enabled "smart card" such as
    * a [YubiKey](https://www.yubico.com/products/yubikey-hardware/)
    * a [Nitrokey](https://www.nitrokey.com/)
    * an [OpenPGP card](https://www.g10code.com/p-card.html)
    * ...

    containing an RSA key with the "Authentication" capability.

## Installation & Usage
  Install [smart-ssh]() from the Chrome Web Store, start the app and follow the instructions.

## Contributing
See [CONTRIBUTING.md](https://github.com/FabianHenneke/smart-ssh/blob/master/CONTRIBUTING.md).

## Possible improvements
  * Support for the PIV applet (which supports ECC keys)

## License
[MIT](https://github.com/FabianHenneke/smart-ssh/blob/master/LICENSE)
