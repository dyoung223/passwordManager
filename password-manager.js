"use strict";

/********* External Imports ********/

const { byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray, stringToByteArray } = require("./lib");
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
      ivs: {},
      tag: "",
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
    //------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
    //TODO CHANGE THIS BACK TO RANDOM SALT BEFORE SUBMISSION    
    let salt = genRandomSalt(16);
    //let salt = "";
    //------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
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
    
    let hash = byteArrayToString(await subtle.digest("SHA-256", repr))
    if(trustedDataCheck != null && hash != trustedDataCheck){ //TODO how is datacheck optional?
      throw "Integrity check in load has failed!!!";
    }
    
    //let reprDump = JSON.parse(repr)
    let reprData = JSON.parse(repr) //reprDump.data
    let tag = reprData.tag
    reprData.tag = "" 	//temp clear tag for tag comparison


    let pbkdf2params = {
      name : "PBKDF2",
      iterations : Keychain.PBKDF2_ITERATIONS,
      "salt" : reprData.salt,
      hash : "SHA-256"
    }

    let rawKey = await subtle.importKey("raw", password, pbkdf2params, false, ["deriveKey"]);
    let encKey = await subtle.deriveKey(pbkdf2params, rawKey, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
    let macKey = await subtle.deriveKey(pbkdf2params, rawKey, {name: "HMAC", length: 256, hash: "SHA-256"}, false, ["sign", "verify"]);

    let dataJson = JSON.stringify(reprData)
    let computedTag = byteArrayToString(await subtle.sign("HMAC", macKey, dataJson))

    if (computedTag != tag){
      throw "Integrity check in load has failed!!! against possible swap";
    }
    
    let kc = new Keychain(encKey, macKey, reprData.salt)
    kc.data = reprData
    //set tag because it was previously cleared for comparison
    kc.data.tag = tag
    
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
    this.data.tag = ""
    let dataJson = JSON.stringify(this.data)
    let tag =  byteArrayToString(await subtle.sign("HMAC", this.secrets.macKey, dataJson))
    /*let dump = {
      data: this.data,
      "tag": tag
    }*/
    
    //let dumpJson = JSON.stringify(dump)
    this.data.tag = tag
    let dumpJson = JSON.stringify(this.data)

    let hash = byteArrayToString(await subtle.digest("SHA-256", dumpJson))
    return [dumpJson, hash]
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
    let iv = Buffer.from(this.data.ivs[hash], "binary")

    let params = {
      name: "AES-GCM",
      "iv": iv
    } // can also pass additional data
    return subtle.decrypt(params, this.secrets.encKey, Buffer.from(this.data.kvs[hash], "binary")).then((arrayBuf) => {
      let padValue = byteArrayToString(arrayBuf)
      return padValue.slice(0,padValue.lastIndexOf("1"))
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
    //---------------------------------------------------------------------------------------------------------------------------//
    // TODO Change this to randomSalt when submitting to gradescope
    /*
    let iv = new ArrayBuffer(16); 
    for (let i = 0; i < 16; i++) {
      iv[i] = 0;
    }
    */
    let iv = genRandomSalt(16)
    //---------------------------------------------------------------------------------------------------------------------------//
    let params = {
      name: "AES-GCM",
      "iv": iv
    } // can also pass additional data
    
    let padValue = value + "1"
    padValue = padValue.padEnd(65, '0')
    let hash = byteArrayToString(await subtle.sign("HMAC", this.secrets.macKey, name))

    this.data.ivs[hash] = Buffer.from(iv).toString("binary")
    
    let encValue = await subtle.encrypt(params, this.secrets.encKey, padValue)
    this.data.kvs[hash] = Buffer.from(encValue).toString("binary")
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
        delete this.data.ivs[hash]
        return true
      }
    )
  };

  static get PBKDF2_ITERATIONS() { return 100000; }
};

module.exports = {
  Keychain: Keychain
}
