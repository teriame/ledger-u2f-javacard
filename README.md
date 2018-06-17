Ledger U2F Applet
=================

# Overview

This is a fork of [ledger-u2f-javacard](https://github.com/LedgerHQ/ledger-u2f-javacard).

It was modified to work with 3.0.1 java cards (ledger-u2f-javacard only works for 3.0.5).

It uses STILL no proprietary vendor API.

I updated the README (the original one was outdated) and provide the steps to generate your own certificate and upload it to your card! In addition, I changed the package AID to `A0:00:00:06:47:2F:01:01` and the app AID to `A0:00:00:06:47:2F:00:01` (standard AID for U2F over [NFC](https://fidoalliance.org/specs/fido-u2f-nfc-protocol-id-20150514.pdf)) so that you can use it with Google Authenticator and Chrome.

# Building 

- Optional: Change the `JC_SELECTED` variable in build.gradle to a SDK you want (default: SDK 3.0.3)
- Run `gradlew buildJavaCard`

# Certificate

The app wants a `ecdsa-with-SHA256` signed key on the P-256 (`prime256v1`) curve. As we have no access to a certified signing oracle we will self sign it.
- `openssl ecparam -name prime256v1 -out param.pem` creates the ec parameters
- `openssl ecparam -in param.pem -genkey -noout -out key.pem` creates the private key
- `openssl ec -noout -text -in key.pem` Shows the private key in hex. Key has to be exactly 32 bytes. If openssl shows a leading 00 remove it, it is just a signing byte.
- `openssl req -new -sha256 -key key.pem -out csr.csr -subj "CN=Something"` Generate a CSR (I filled only the CN field in, to keep the certificate small)
- `openssl req -x509 -sha256 -days 99999 -key key.pem -in csr.csr -out certificate.pem` Sign it
- `openssl x509 -in certificate.pem -out certificate.der -outform der` convert PEM to DER (the applet wants the cert in DER format)
- `xxd -ps certificate.der` get binary DER in HEX

# Installing 

Load the CAP file using your favorite third party software.

 
The following install parameters are expected : 

- 1 byte flag : provide 01 to pass the current [Fido NFC interoperability tests](https://github.com/google/u2f-ref-code/tree/master/u2f-tests), or 00 
- 2 bytes length (big endian encoded) : length of the attestation certificate to load, supposed to be using a private key on the P-256 curve 
- 32 bytes : private key of the attestation certificate 

Before using the applet, the attestation certificate shall be loaded using a proprietary APDU 

| CLA | INS | P1            | P2           | L                    | Data                    |
| --- | --- | ------------- | ------------ | -------------------- | ----------------------- |
| F0  | 01  | offset (high) | offset (low) | length of data chunk | Certificate data chunk  | 

# Example

Example cert and key is from [here](https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html#examples).

- Install parameters:
(flag: 00, length: 01 40, 32 byte key without signing byte):
<pre>
00 01 40 f3 fc cc 0d 00 d8 03 19 54 f9 08 64 d4 3c 24 7f 4b f5 f0 66 5c 6b 50 cc 17 74 9a 27 d1 cf 76 64 
</pre>

- Initialisation parameters:
  1. Select applet:
  <pre>
  00 A4 04 00 08 A0 00 00 06 47 2F 00 01
  </pre>
  2. First 128 Byte of the certificate:
  <pre>
  F0 01 00 00 80 30 82 01 3c 30 81 e4 a0 03 02 01 02 02 0a 47 90 12 80 00 11 55 95 73 52 30 0a 06 08 2a 86 48 ce 3d 04 03 02 30 17 31 15 30 13 06 03 55 04 03 13 0c 47 6e 75 62 62 79 20 50 69 6c 6f 74 30 1e 17 0d 31 32 30 38 31 34 31 38 32 39 33 32 5a 17 0d 31 33 30 38 31 34 31 38 32 39 33 32 5a 30 31 31 2f 30 2d 06 03 55 04 03 13 26 50 69 6c 6f 74 47 6e 75 62 62 79 2d 30 2e 34 2e 31 2d 34 37 39 30
  </pre>
  3. Next 128 Byte of the certificate:
  <pre>
  F0 01 00 80 80 31 32 38 30 30 30 31 31 35 35 39 35 37 33 35 32 30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00 04 8d 61 7e 65 c9 50 8e 64 bc c5 67 3a c8 2a 67 99 da 3c 14 46 68 2c 25 8c 46 3f ff df 58 df d2 fa 3e 6c 37 8b 53 d7 95 c4 a4 df fb 41 99 ed d7 86 2f 23 ab af 02 03 b4 b8 91 1b a0 56 99 94 e1 01 30 0a 06 08 2a 86 48 ce 3d 04 03 02 03 47 00 30 44 02 20 60 cd
  </pre>
  4. Last 64 Byte of the certificate:
  <pre>
  F0 01 01 00 40 b6 06 1e 9c 22 26 2d 1a ac 1d 96 d8 c7 08 29 b2 36 65 31 dd a2 68 83 2c b8 36 bc d3 0d fa 02 20 63 1b 14 59 f0 9e 63 30 05 57 22 c8 d8 9b 7f 48 88 3b 90 89 b8 8d 60 d1 d9 79 59 02 b3 04 10 df
  </pre>

# Testing on Android 

  - Download [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)
  - Test on http://u2fdemo.appspot.com or https://demo.yubico.com/u2f from Chrome
  - For additional API reference and implementations, check [the reference code](https://github.com/google/u2f-ref-code), the [beta NFC API](https://github.com/google/u2f-ref-code/blob/no-extension/u2f-gae-demo/war/js/u2f-api.js) and [Yubico guide](https://www.yubico.com/applications/fido/) 

# License

This application is licensed under [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0)
