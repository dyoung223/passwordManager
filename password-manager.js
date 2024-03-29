"use strict";

/********* External Imports ********/

const { byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor(encKey, macKey, salt) {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      "salt": salt,
      kvs: {},
      version: "CS 255 Password Manager v1.0"
    };

    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      "encKey" : encKey,
      "macKey" : macKey
    };

    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;
  };

  /** 
    * Creates an empty keychain with the given password. Once the constructor
    * has finished, the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void , KVS?
    */
  static async init(password) {
    
    //let salt = genRandomSalt();
    let salt = "";
    let pbkdf2params = {
      name : "PBKDF2",
      iterations : Keychain.PBKDF2_ITERATIONS,
      "salt" : salt,
      hash : "SHA-256"
    }

    let rawKey = await subtle.importKey("raw", password, pbkdf2params, false, ["deriveKey"]);
    
    let encKey = await subtle.deriveKey(pbkdf2params, rawKey, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
    let macKey = await subtle.deriveKey(pbkdf2params, rawKey, {name: "HMAC", length: 256, hash: "SHA-256"}, false, ["sign", "verify"]);

    return new Keychain(encKey, macKey, salt);
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    
    //Do you need to check for the password before any of this functionality is allowed?
    
    //Is this the right way of checking if the trustedDataChecksum matches the current contents
    let reprData = JSON.parse(repr)

    let pbkdf2params = {
      name : "PBKDF2",
      iterations : Keychain.PBKDF2_ITERATIONS,
      "salt" : reprData.salt,
      hash : "SHA-256"
    }

    let rawKey = await subtle.importKey("raw", password, pbkdf2params, false, ["deriveKey"]);
    
    let encKey = await subtle.deriveKey(pbkdf2params, rawKey, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
    let macKey = await subtle.deriveKey(pbkdf2params, rawKey, {name: "HMAC", length: 256, hash: "SHA-256"}, false, ["sign", "verify"]);

    
    let kc = new Keychain(encKey, macKey, reprData.salt)
    kc["data"] = reprData
    let kcJson = JSON.stringify(kc)
    let hash = byteArrayToString(await subtle.digest("SHA-256", kcJson))
    if(hash != trustedDataCheck){
      throw "Integrity check in load has failed!!!";
    }
    
    return kc
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  async dump() {
    if (!("ready" in this) || !this.ready){
      return null
    }
    let dataJson = JSON.stringify(this.data)
    //Is this supposed to be a hash of the checksum or a hash of the actual "keychain contents" as per proj handout
    let thisJson = JSON.stringify(this)
    let hash = byteArrayToString(await subtle.digest("SHA-256", thisJson))
    
    return [dataJson, hash]
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    if (!("ready" in this) || !this.ready){
      throw "Keychain not initialized.";
    }
    
    let hash =  byteArrayToString(await subtle.sign("HMAC", this.secrets.macKey, name))

    if (!(hash in this.data.kvs)){
      return null
    }
  
    // TODO throw if tampering detected

    let iv = new ArrayBuffer(16); 
    for (let i = 0; i < 16; i++) {
      iv[i] = 0;
    }

    let params = {
      name: "AES-GCM",
      "iv": iv
    } // can also pass additional data
    return subtle.decrypt(params, this.secrets.encKey, this.data.kvs[hash]).then((arrayBuf) => {
      return byteArrayToString(arrayBuf)
    })
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    if (!("ready" in this) || !this.ready){
      throw "Keychain not initialized.";
    }
    let iv = new ArrayBuffer(16); 
    for (let i = 0; i < 16; i++) {
      iv[i] = 0;
    }

    let params = {
      name: "AES-GCM",
      "iv": iv
    } // can also pass additional data

    let hash = byteArrayToString(await subtle.sign("HMAC", this.secrets.macKey, name))
    let encValue = await subtle.encrypt(params, this.secrets.encKey, value)
    this.data.kvs[hash] = encValue
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if (!("ready" in this) || !this.ready){
      throw "Keychain not initialized.";
    }

    let hashPromise = subtle.sign("HMAC", this.secrets.macKey, name)

    return hashPromise.then((hashArray) => 
      {
        let hash = byteArrayToString(hashArray)  
        if (!(hash in this.data.kvs)){
          // TODO is this right?
          return false
        }

        delete this.data.kvs[hash]
        return true
      }
    )
  };

  static get PBKDF2_ITERATIONS() { return 100000; }
};

module.exports = {
  Keychain: Keychain
}
