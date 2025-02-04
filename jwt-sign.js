var jwt = require('jsonwebtoken');


module.exports = function(RED) {
    function JwtSign(config) {
        RED.nodes.createNode(this,config);
        this.name = config.name;
        this.algorithm = config.algorithm; 
        this.mode = config.mode;    
        this.secret = this.credentials.secret;   
        this.secretType = config.secretType;    
        this.privateKey = this.credentials.privateKey; 
        this.privateKeyType = config.privateKeyType;
        this.jwkid = config.jwkid;
        this.jwkidType = config.jwkidType;
        this.jwkurl = config.jwkurl;
        this.jwkurlType = config.jwkurlType;
        this.expiresIn = config.expiresIn;
        this.audience = config.audience;
        this.audienceType = config.audienceType;
        this.issuer = config.issuer;
        this.issuerType = config.issuerType;
        this.sign = config.sign;
        this.signType = config.signType;
        this.notBefore = config.notBefore;
        this.notBeforeType = config.notBeforetype;

        let node = this;
        
        node.on('input', async function(msg) {
            try {
                let sign = await evaluateNodeProperty(node.sign, node.signType, node, msg)
                if(!sign)
                    throw new Error('No data found to sign')
                if(typeof sign !== 'object' || sign === null || Array.isArray(sign)){
                    sign = {
                        data: sign
                    }
                }
                let options = { expiresIn: parseInt(node.expiresIn),  algorithm: node.algorithm }
                const audience = await evaluateNodeProperty(node.audience, node.audienceType, node, msg);
                if(audience){
                    options.audience = audience
                }
                const issuer = await evaluateNodeProperty(node.issuer, node.issuerType, node, msg);
                if(issuer){
                    options.issuer = issuer
                }
                const notBefore = await evaluateNodeProperty(node.notBefore, node.notBeforeType, node, msg);
                if(notBefore){
                    options.notBefore = notBefore
                }
                let secretOrPrivateKey = ''
                switch (node.mode) {
                    case 'secret':{
                        secretOrPrivateKey = await evaluateNodeProperty(node.secret, node.secretType, node, msg);
                        if(!secretOrPrivateKey)
                            throw new Error('Value not found for variable "Secret"')                        
                    }break;
                    case 'private-key':{
                        secretOrPrivateKey = await evaluateNodeProperty(node.privateKey, node.privateKeyType, node, msg);
                        if(!secretOrPrivateKey)
                            throw new Error('Value not found for variable "Private Key"')
                    }break;
                }
                var token = jwt.sign(sign, secretOrPrivateKey , options);
                msg.payload = token
                node.send(msg);
            } catch (error) {
                node.error(error.message, msg);
            }
            
        });
    }
    RED.nodes.registerType("jwt sign", JwtSign, { 
        credentials: {
            secret: { type:"password" },
            privateKey: { type:"password" }
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
