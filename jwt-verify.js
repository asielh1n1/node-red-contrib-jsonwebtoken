var jwt = require('jsonwebtoken');
var jwksClient = require('jwks-rsa');
var validate = require("validate.js");

validate.validators.equal = function(value, options, key, attributes) {
    if (options.typeValue == 'num' && attributes[key] !== parseFloat(options.attribute)) {
        return options. message || `^${key} must be equal to ${options.attribute}`;
    }
    if (options.typeValue == 'str' && attributes[key] !== options.attribute) {
        return options. message || `^${key} must be equal to ${options.attribute}`;
    }
    if (options.typeValue == 'json' && JSON.stringify(attributes[key]) !== options.attribute) {
        return options. message || `^${key} must be equal to ${options.attribute}`;
    }
};

// Definimos la función de validación personalizada
validate.validators.regexp = function(value, options, key, attributes) {
    const regex = new RegExp(options.attribute,'ig');
    if(!regex.test(value))
        return options. message || `^${key} does not match the regular expression ${options.attribute}`;
};

// Definir la constraint personalizada
validate.validators.includesAny = function(value, options, key, attributes) {
    if (!Array.isArray(value)) {
        return `The value ${JSON.stringify(value)} is not an array`;
    }
    if (Array.isArray(options.attribute)) {
        const isValid = value.some(x => options.attribute.includes(x));
        if (!isValid) {
            return options. message || `Must include at least one value from the list: ${options.attribute.join(', ')}`;
        }
    }
    if(typeof options.attribute == 'string'){
        const isValid = value.some(x => x == options.attribute);
        if (!isValid) {
            return options. message || `Must include at least one value from ${options.attribute}`;
        }
    }
    
};

module.exports = function(RED) {
    function JwtVerify(config) {
        RED.nodes.createNode(this,config);
        this.name = config.name;
        this.algorithms = config.algorithms; 
        this.mode = config.mode;    
        this.secret = this.credentials.secret;   
        this.secretType = config.secretType;    
        this.publicKey = this.credentials.publicKey; 
        this.publicKeyType = config.publicKeyType;
        this.jwkid = config.jwkid;
        this.jwkidType = config.jwkidType;
        this.jwkurl = config.jwkurl;
        this.jwkurlType = config.jwkurlType;
        this.ignoreExpiration = config.ignoreExpiration;
        this.ignoreExpirationType = config.ignoreExpirationType;
        this.ignoreNotBefore = config.ignoreNotBefore;
        this.ignoreNotBeforeType = config.ignoreNotBeforeType;
        this.audience = config.audience;
        this.audienceType = config.audienceType;
        this.issuer = config.issuer;
        this.issuerType = config.issuerType;
        this.token = config.token;
        this.maxAge = config.maxAge;
        this.maxAgeType = config.maxAgeType;
        this.constraints = config.constraints;

        let node = this;
        
        node.on('input', async function(msg) {
            try {
                let token = ""                
                if(node.token == 'payload' || node.token == 'token'){
                    token = msg[node.token]
                } else if(node.token == 'bearer_authorization_header' && msg.req !== undefined && msg.req.get("authorization") !== undefined){
                    var authz = msg.req.get("authorization").split(" ")
                    token = authz.length == 2 && authz[0] === 'Bearer' ? authz[1]: null
                }else if(node.token == 'query_params' && msg.req.query.access_token !== undefined){
                    token = msg.req.query.access_token;
                }
                if(!token)
                    throw new Error('JWT token not found')
                const ignoreExpiration = RED.util.evaluateNodeProperty(node.ignoreExpiration, node.ignoreExpirationType, node)
                const ignoreNotBefore = RED.util.evaluateNodeProperty(node.ignoreNotBefore, node.ignoreNotBeforeType, node)
                let options = { ignoreExpiration, ignoreNotBefore }
                const audience = await evaluateNodeProperty(node.audience, node.audienceType, node, msg);
                if(audience){
                    options.audience = audience
                }
                const issuer = await evaluateNodeProperty(node.issuer, node.issuerType, node, msg);
                if(issuer){
                    options.issuer = issuer
                }
                const maxAge = await evaluateNodeProperty(node.maxAge, node.maxAgeType, node, msg);
                if(maxAge){
                    options.maxAge = maxAge
                }
                if(node.algorithms)
                    options.algorithms = node.algorithms.split(',')
                switch (node.mode) {
                    case 'secret':{
                        const secret = await evaluateNodeProperty(node.secret, node.secretType, node, msg);
                        if(!secret)
                            throw new Error('Value not found for variable "Secret"')
                        msg.payload = jwt.verify(token, secret , options);
                    }break;
                    case 'public-key':{
                        const publicKey = await evaluateNodeProperty(node.publicKey, node.publicKeyType, node, msg);
                        if(!publicKey)
                            throw new Error('Value not found for variable "Private Key"')
                        msg.payload = jwt.verify(token, publicKey , options);
                    }break;
                    case 'jwtid':{
                        const jwkid = await evaluateNodeProperty(node.jwkid, node.jwkidType, node, msg);
                        if(!jwkid)
                            throw new Error('Value not found for variable "JWK KID"')
                        const jwkurl = await evaluateNodeProperty(node.jwkurl, node.jwkurlType, node, msg);
                        if(!jwkurl)
                            throw new Error('Value not found for variable "JWK URL"')
                        var client = jwksClient({
                            jwksUri: jwkurl
                        });
                        const key = await client.getSigningKey(jwkid);
                        const signingKey = key.getPublicKey() || key.rsaPublicKey();
                        options.algorithms = [key.alg]
                        msg.payload = jwt.verify(token, signingKey, options);
                    }break;
                }
                if(node.constraints && Array.isArray(node.constraints)){
                    const constraints = generateConstraints(node.constraints)
                    let result = validate(msg.payload, constraints)
                    if(result){
                        throw new Error(`Claims validation failed. ${JSON.stringify(result)}`)
                    }
                } 
                node.send(msg);
            } catch (error) {
                node.error(error.message, msg);
            }
            
        });
    }
    RED.nodes.registerType("jwt verify", JwtVerify, { 
        credentials: {
            secret: { type:"password" },
            publicKey: { type:"password" }
        }
    });

    function evaluateNodeProperty(value, type, node, msg){
        return new Promise((resolve, reject)=>{
            RED.util.evaluateNodeProperty(value, type, node, msg, (err, result) => {
                if (err) {
                    reject(error)
                } else {
                    resolve(result)
                }
            })
        })
    }
}

function generateConstraints(constraints){
    let result = {}
    constraints.forEach(x=>{
        if(!result[x.property])
            result[x.property] = {}
        typeContrain(result[x.property], x.validator, x.value, x.error, x.typeValue)
    })
    return result
}

function typeContrain(property, validator, value, error, typeValue) {
    switch (validator) {
        case 'presence':{
            property['presence'] = {
                message: error || null
            }
        }break;
        case 'equal':{
            property['equal'] = {
                attribute: value,
                message: error || null,
                typeValue: typeValue
            }
        }break;
        case 'regexp':{
            property['regexp'] = {
                attribute: value,
                message: error || null
            }
        }break;
        case 'maxlength':{
            property['length'] = {
                maximum: parseInt(value),
                message: error || null
            }
        }break;
        case 'minlength':{
            property['length'] = {
                minimum: parseInt(value),
                message: error || null
            }
        }break;
        case 'type':{
            property['type'] = {
                type: value,
                message: error || null
            }
        }break;
        case 'inclusion':{
            property['inclusion'] = {
                within: JSON.parse(value),
                message: error || null
            }
        }break;
        case 'exclusion':{
            property['exclusion'] = {
                within: JSON.parse(value),
                message: error || null
            }
        }break;
        case 'includesAny':{
            let result = null
            try {
                result = JSON.parse(value)
            } catch (error) {
                result = value
            }
            property['includesAny'] = {
                attribute: result,
                message: error || null
            }
        }break;
    }
}
