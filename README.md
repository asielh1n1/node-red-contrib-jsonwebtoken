This Node-RED node allows signing and validating JSON Web Tokens (JWT).

## Install
node-red-contrib-jsonwebtoken is available in the Node-RED Palette Manager. To install it:

* Open the menu in the top-right of Node-RED
* Click "Manage Palette"
* Switch to the "Install" tab
* Search node-red-contrib-jsonwebtoken
* Install the node-red-contrib-jsonwebtoken package
The nodes will then be available in your editor for you to get started.

It is also possible to install it via npm:
```
npm install node-red-contrib-jsonwebtoken
```

## Node jwt-sign

This node allows you to sign and validate JSON Web Token (JWT)

### Inputs

: payload (string | object) :  the payload of the message to publish.


### Outputs

1. Standard output
: payload (string) : the standard output of the command.

2. Standard error
: payload (object) : the standard error of the command.

### Form fields

* **Mode**: Mode to use for verifying the token.
* **Algorithm**: Token encryption algorithm, it is recommended to use a private key as it provides more security to the token.
* **Private Key**: In case of selecting the private key mode, the source of the key must be specified. The input variable must be of type buffer, for any of the selected cases, whether it comes from the message payload or environment variables.
* **Secret**: In the case of signing the token with a secret key, the source of the key must be specified, which can be a string, input message, or environment variable.
* **Expires In**: Token expiration time in seconds.
* **Data to Sign**: Source of the data to be signed, the input must be a JavaScript object. If the input is different from an object, the token is signed with the 'data' claim and the data is added there.
* **Audience**: Allows configuring the audience of the token.
* **Issuer**: Allows configuring the issuer of the token.
* **Not Before**: The "Not Before" (NBF) field in a token is used to specify the moment from which the token is valid. This means that the token will not be accepted by the server before the date and time specified in this field. The value is expressed in seconds.
* **Keyid**: The Keyid field enables the inclusion of the kid header in token signatures.

## Node jwt-verify

This node allows verifying the authenticity of a JSON Web Token (JWT).

### Inputs

: payload (string) :  the payload of the message to publish.


### Outputs

1. Standard output
: payload (object) : the standard output of the command.

2. Standard error
: payload (object) : the standard error of the command.

### Form fields

* **Mode**: Mode to use for verifying the token.
* **Private Key**: In case of selecting the private key mode, the source of the key must be specified. The input variable must be of type buffer, for any of the selected cases, whether it comes from the message payload or environment variables.
* **Secret**: In the case of signing the token with a secret key, the source of the key must be specified, which can be a string, input message, or environment variable.
* **Token origin**: Source of the token.
* **Algorithms**: Optional, if not specified a defaults will be used based on the type of key provided
* **Ignore Expiration**: The default value is false; if true, it bypasses the token's expiration date.
* **Ignore "NotBefore"**: The default value is false; if true, it bypasses the validation that the token is validated before the specified date.
* **Validate Audience**: Validates that the audience is correct.
* **Validate Issuer**: Validates that the token issuer is correct.
* **Validate Max Age**: The "max age" in a JSON Web Token (JWT) refers to the maximum time a token can be considered valid from the moment it was issued. The value is expressed in seconds
* **Validate Claims**: Allows validating the different claims of the token, ideal for validating the scopes, roles, and users with access to some API resources. It is also possible to validate objects in depth like "user.roles[0]"
    

## Examples

Review the node examples for more clarity on how to use it. You can import it in the import menu and search for the node example "node-red-contrib-jsonwebtoken" or the json for the site [GitHub](https://github.com/asielh1n1/node-red-contrib-jsonwebtoken/blob/main/examples/flows.json).

## References

 - [Json Web Token](https://www.npmjs.com/package/jsonwebtoken)
