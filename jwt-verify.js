


module.exports = function(RED) {
    var jwt = require('jsonwebtoken');
    var jwksClient = require('jwks-rsa');
    const Ajv = require("ajv")
    const ajv = new Ajv({ allErrors: true, messages: true, $data: true })
    require("ajv-formats")(ajv);
    require("ajv-errors")(ajv);

    function JwtVerify(config) {
        RED.nodes.createNode(this,config);
        this.name = config.name;
        this.algorithms = config.algorithms; 
        this.mode = config.mode;    
        this.secret = config.secret;   
        this.secretType = config.secretType;    
        this.publicKey = config.publicKey; 
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
                    let schema = {
                        type: "object",
                        properties: {},
                        required: [],
                        additionalProperties: true,
                        errorMessage: {required:{}}
                    };
                    schema = generateConstraints(node.constraints, schema)
                    const validate = ajv.compile(schema)
                    const valid = validate(msg.payload)
                    if(!valid){
                        msg.payload = validate.errors.map(x=> x.message)
                        node.error(JSON.stringify(validate.errors), msg);
                        return;
                    }
                } 
                node.send(msg);
            } catch (error) {
                node.error(error.message, msg);
            }
            
        });
    }
    RED.nodes.registerType("jwt verify", JwtVerify);

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
    
    function generateConstraints(constraints, schema){
        constraints.forEach(x=>{
            typeContrain(x.property, x.validator, x.value, x.typeValue,x.error, schema)
        })
        return schema
    }
    
    function typeContrain(property, validator, value, typeValue, error, schema) {
        if(!schema.properties[property]){
            schema.properties[property] = {
                errorMessage: {}
            }
        }
        switch (validator) {
            case 'required':{
                schema.required.push(property)
                schema.errorMessage.required[property] = error || `The ${property} field is required`
            }break;
            case 'type':{
                schema.properties[property].type = value
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type ${value}`
            }break;
            case 'email':{
                schema.properties[property].type = 'string'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type string`
                schema.properties[property].format = 'email'
                schema.properties[property].errorMessage.format = error || `The ${property}  field is not a valid email address.`
            }break;
            case 'equal':{
                schema.properties[property].const = value
                schema.properties[property].errorMessage.const = error || `The ${property} field must be equal to ${value}`
            }break;
            case 'equality':{
                schema.properties[property].const = { $data: `1/${value}` }
                schema.properties[property].errorMessage.const = error || `The value of the ${property} field must be equal to the value of the ${value} field.`
            }break;
            case 'pattern':{
                schema.properties[property].pattern = value
                schema.properties[property].errorMessage.pattern = error || `The field ${property} does not match the regular expression ${value}`
            }break;
            case 'maxlength':{
                schema.properties[property].type = 'string'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type string`
                schema.properties[property].maxLength = parseInt(value)
                schema.properties[property].errorMessage.maxLength = error || `The ${property} field must have a maximum size of ${value}`
            }break;
            case 'minlength':{
                schema.properties[property].type = 'string'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type string`
                schema.properties[property].minLength = parseInt(value)
                schema.properties[property].errorMessage.minLength = error || `The ${property} field must have a minimum size of ${value}`
            }break;
            case 'url':{
                schema.properties[property].type = 'string'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type string`
                schema.properties[property].format = 'uri'
                schema.properties[property].errorMessage.format = error || `The ${property} field is not a valid URL.`
            }break;
            case 'date':{
                schema.properties[property].format = 'date'
                schema.properties[property].errorMessage.format = error || `The ${property} field is not a valid date.`
            }break;
            case 'inclusion':{
                schema.properties[property].type = 'array'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type array`                
                schema.properties[property].enum = JSON.parse(value)
                schema.properties[property].errorMessage.enum = error || `The value of the ${property} field is not included in the ${value} list.`
            }break;
            case 'exclusion':{
                schema.properties[property].type = 'array'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type array`                   
                schema.properties[property].not = {enum:JSON.parse(value)}
                schema.properties[property].errorMessage.not = error || `The value of the field ${property} cannot be included in the list ${value}.`
            }break;
            case 'ipv4':{
                schema.properties[property].type = 'string'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type string`
                schema.properties[property].format = 'ipv4'
                schema.properties[property].errorMessage.format = error || `The ${property} field is not a valid IPv4.`
            }break;
            case 'ipv6':{
                schema.properties[property].type = 'string'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type string`
                schema.properties[property].format = 'ipv6'
                schema.properties[property].errorMessage.format = error || `The ${property} field is not a valid IPv6.`
            }break;
            case 'hostname':{
                schema.properties[property].type = 'string'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type string`
                schema.properties[property].format = 'hostname'
                schema.properties[property].errorMessage.format = error || `The ${property} field is not a valid hostname.`
            }break;
            case 'json':{
                schema.properties[property].format = 'json-pointer'
                schema.properties[property].errorMessage.format = error || `The ${property} field is not a valid JSON.`
            }break;
            case 'maximum_number':{
                schema.properties[property].type = 'number'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type number`
                schema.properties[property].maximum = parseFloat(value)
                schema.properties[property].errorMessage.maximum = error || `The value of the ${property} field cannot be greater than ${value}.`
            }break;
            case 'minimum_number':{
                schema.properties[property].type = 'number'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type number`
                schema.properties[property].minimum = parseFloat(value)
                schema.properties[property].errorMessage.minimum = error || `The value of the ${property} field cannot be less than ${value}.`
            }break;
            case 'maximum_items':{
                schema.properties[property].type = 'array'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type array`
                schema.properties[property].maxItems = parseFloat(value)
                schema.properties[property].errorMessage.maxItems = error || `The ${property} field cannot have more than ${value} elements..`
            }break;
            case 'minimum_items':{
                schema.properties[property].type = 'array'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type array`
                schema.properties[property].minItems = parseFloat(value)
                schema.properties[property].errorMessage.minItems = error || `The ${property} field cannot have less than ${value} elements.`
            }break;
            case 'uuid':{
                schema.properties[property].type = 'string'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type string`
                schema.properties[property].format = 'uuid'
                schema.properties[property].errorMessage.format = error || `The field ${property} is not a valid UUID`
            }break;
            case 'any_of':{
                schema.properties[property].type = 'array'
                schema.properties[property].errorMessage.type = error || `The ${property} field must be of type array`
                const list = JSON.parse(value)
                schema.properties[property].contains = { 
                    anyOf: list.map(x=> {
                        return { const: x }
                    })
                }
                schema.properties[property].errorMessage.contains = error || `Field ${property} does not contain any value from list ${value}`
            }break;
        }
    }
}
