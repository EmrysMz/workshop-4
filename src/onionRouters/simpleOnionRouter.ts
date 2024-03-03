import bodyParser from "body-parser";
import express from "express";

import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPrvKey,exportPubKey } from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  const dictPrvKey: { [key: number]: string | null } = {};
  const dictPbKey: { [key: number]: string | null } = {};

  const keyPair = await generateRsaKeyPair();
  
  const privateKey = await exportPrvKey(keyPair.privateKey);
  const publicKey = await exportPubKey(keyPair.publicKey);

  dictPrvKey[nodeId] = privateKey;
  dictPbKey[nodeId] = publicKey;

  const body = { nodeId, pubKey: publicKey };

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
    const requestedNodeId = parseInt(req.query.nodeId as string);
    const privateKey = dictPrvKey[requestedNodeId];
    if (privateKey) {
      res.json({ result: privateKey });
    } else {
      res.status(404).json({ error: "Private key not found for the requested node" });
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}