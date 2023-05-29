import { ChangeEvent, FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { openDB } from "idb";
import { v4 as uuidv4 } from "uuid";

function RegisterLogin() {
  const [username, setUsername] = useState("");

  const handleChange = (event: ChangeEvent) => {
    setUsername(event.currentTarget.value);
  };

  const login = async () => {
    const db = await openDB("keyval-store", 1, { //Probably should verify the success of this
      upgrade(db) {
        db.createObjectStore("keyval");
      },
    });
    const existingEntry = await db.get("keyval", username);
    if (existingEntry == undefined) {
      alert("No User");
      return;
    }
    let parsedEntry = JSON.parse(existingEntry);
    let idBuffer = new Int32Array(parsedEntry.id);
    let credential: PublicKeyCredential = await navigator.credentials.get({
      publicKey: {
        challenge: new Uint8Array([139, 66, 181, 87, 7, 203]), //Garbage Challenge key. You should recieve a 29 byte unique challenge from server
        allowCredentials: [
          {
            type: "public-key",
            id: idBuffer,
          },
        ],
        userVerification: "required",
      },
    });
    let pubkey = new Uint8Array(parsedEntry.pubkey);
    const publicKey = await window.crypto.subtle.importKey(
      "spki",
      pubkey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const signature = credential.response.signature;
    // Signature Data AuthenticatorData+HashedClientDataJson

    const clientDataJSON = credential.response.clientDataJSON;

    const authenticatorData = new Uint8Array(
      credential.response.authenticatorData
    );

    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", clientDataJSON)
    );
    const signedData = new Uint8Array( //Need to concat signature data to verify signature
      authenticatorData.length + clientDataHash.length
    );
    signedData.set(authenticatorData);
    signedData.set(clientDataHash, authenticatorData.length);

    // Convert signature from ASN.1 sequence to "raw" format.
    // Signature is returned ASN.1 wrapped and subtle verify requires a raw signature
    const usignature = new Uint8Array(signature);
    const rStart = usignature[4] === 0 ? 5 : 4;
    const rEnd = rStart + 32;
    const sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2;
    const r = usignature.slice(rStart, rEnd);
    const s = usignature.slice(sStart);
    const rawSignature = new Uint8Array([...r, ...s]);

    const verification = await window.crypto.subtle.verify(
      //ES256
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey, //from generateKey or importKey above
      rawSignature, //ArrayBuffer of the signature
      signedData.buffer
    );
    if (verification) {
      alert("Verified User!");
    } else {
      alert("Failed to verify User");
    }
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (username == "") {
      alert("No username????");
      return;
    }
    const id = new ArrayBuffer(16);
    uuidv4(undefined, id); //Weird syntax uuid has to fill an ArrayBuffer
    const db = await openDB("keyval-store", 1, {
      upgrade(db) {
        db.createObjectStore("keyval");
      },
    });
    let credential: PublicKeyCredential = await navigator.credentials.create({
      publicKey: {
        challenge: new Uint8Array([117, 61, 252, 231, 191, 241]), //Garbage Challenge key. You should recieve a 29 byte unique challenge from server
        rp: {
          name: "Acme",
        },
        user: {
          id: id,
          name: username,
          displayName: username,
        },
        attestation: "direct",
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], //ES256
      },
    });
    const pubKey: Uint8Array = new Uint8Array(
      credential.response.getPublicKey()
    );
    await db.put( //Probably should verify the success of this
      "keyval",
      JSON.stringify({
        id: Array.from(new Int32Array(credential.rawId)),
        transports: credential.response.getTransports(),
        pubkey: Array.from(pubKey),
      }),
      username
    );
    alert("A name was submitted: " + username);
  };

  return (
    <>
      <h1 className="font-bold my-2">Login or Register</h1>
      <form onSubmit={handleSubmit} className="flex flex-col">
        <label className="flex items-center justify-center my-4 font-bold">
          Username:
          <input
            className="mx-2 p-1"
            type="text"
            value={username}
            onChange={handleChange}
          />
        </label>
        <div className="flex self-center gap-3">
          <button type="submit" className="btn btn-blue">
            Register
          </button>
          <button
            type="button"
            onClick={() => {
              login();
            }}
            className="btn btn-green"
          >
            Login
          </button>
        </div>
      </form>
    </>
  );
}

export default RegisterLogin;
