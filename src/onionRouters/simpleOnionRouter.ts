import bodyParser from "body-parser";
import express from "express";

import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT,BASE_USER_PORT } from "../config";
import { generateRsaKeyPair, exportPrvKey,exportPubKey,rsaDecrypt,rsaEncrypt,createRandomSymmetricKey, importPrvKey,importPubKey,importSymKey,symDecrypt} from "../crypto";


export async function simpleOnionRouter(nodeId: number) {
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  

  const { publicKey, privateKey } = await generateRsaKeyPair();

  
  let privateKeyExport = await exportPrvKey(privateKey);
  let pubKeyExport = await exportPubKey(publicKey);



  const body = { nodeId, pubKey : pubKeyExport, privKey : privateKeyExport};

  const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!registryResponse) {
    throw new Error(`Failed to register node. Request body: ${JSON.stringify(body)}`);
  } else {
    console.log("Node registered");
  }

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    try {
      const privateKeyResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getPrivateKey/${nodeId}`);
  
      if (privateKeyResponse.ok) {
        const privateKeyData = await privateKeyResponse.json() as { result: string };
        const privateKey = privateKeyData.result;
        res.json({ result: privateKey });
      } else {
        throw new Error(`Failed to fetch private key. Status: ${privateKeyResponse.status}`);
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Internal server error" });
    }
  });


  onionRouter.post("/message", async (req, res) => {

    const {message} = req.body;

    const privateKeyResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getPrivateKey/${nodeId}`);
    const privateKeyData = await privateKeyResponse.json() as { result: string };
    const privateKey = privateKeyData.result;

    
    

    const decryptedKey = await rsaDecrypt(message.slice(0,344), await importPrvKey(privateKey));

    

    const decryptedMessage = await symDecrypt(decryptedKey,message.slice(344));

    //const nextDestination = Number(decryptedMessage.slice(0,10));
    const nextDestination = parseInt(decryptedMessage.slice(0,10),10);

    const remainingMessage = decryptedMessage.slice(10);

    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = remainingMessage;
    lastMessageDestination = nextDestination;

   

    await fetch(`http://localhost:${nextDestination}/message`, {method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message: remainingMessage })});

    res.status(200).json({ result: "success" });



 
  });


  

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}