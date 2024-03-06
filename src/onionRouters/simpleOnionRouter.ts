import bodyParser from "body-parser";
import express from "express";

import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT,BASE_USER_PORT } from "../config";
import { generateRsaKeyPair, exportPrvKey,exportPubKey,rsaDecrypt,rsaEncrypt,createRandomSymmetricKey, importPrvKey,importPubKey,importSymKey,symDecrypt} from "../crypto";


export async function simpleOnionRouter(nodeId: number) {
  

  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  

  const { publicKey, privateKey } = await generateRsaKeyPair();

  
  let privateKeyExport = await exportPrvKey(privateKey);
  let pubKeyExport = await exportPubKey(publicKey);



  const body = { nodeId, pubKey : pubKeyExport};

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

  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKeyExport});
  });


  onionRouter.post("/message", async (req, res) => {

    const {message} = req.body;
    

  
    const decryptedKey = await rsaDecrypt(message.slice(0,344), privateKey);

    const decryptedMessage = await symDecrypt(decryptedKey,message.slice(344));
    const nextDest = Number(decryptedMessage.slice(0,10));

    const remainingMessage = decryptedMessage.slice(10);

    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = remainingMessage;
    lastMessageDestination = nextDest;

   

    await fetch(`http://localhost:${nextDest}/message`, {method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message: remainingMessage })});

    res.status(200).json({ result: "message sent to next destination" });



 
  });


  

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}