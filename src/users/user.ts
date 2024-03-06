import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT,BASE_ONION_ROUTER_PORT } from "../config";

import {
  symDecrypt,
  symEncrypt,
  exportSymKey,
  importSymKey,
  createRandomSymmetricKey,
  importPubKey,
  rsaEncrypt,
} from "../crypto";
import { Node } from "../registry/registry";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};


function getRandomCircuit(nodes: Node[], circuitLength: number): Node[] {
  const circuit = [];
  const nodeIds = new Set();

  while (nodeIds.size < circuitLength) {
    const randomIndex = Math.floor(Math.random() * nodes.length);
    const node = nodes[randomIndex];
    if (!nodeIds.has(node.nodeId)) {
      nodeIds.add(node.nodeId);
      circuit.push(node);
    }
  }

  return circuit;
}

export async function user(userId: number) {
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.post("/message", (req, res) => {
    const body = req.body as SendMessageBody;
    lastReceivedMessage = body.message;
    res.send("success");
  });

  _user.post("/sendMessage", async (req, res) => {
    const body = req.body as SendMessageBody;
    const { message, destinationUserId } = body;

    const registryResponse = await fetch("http://localhost:" + REGISTRY_PORT + "/getNodeRegistry");
    const {nodes} = await registryResponse.json() as {nodes : Node[]};

    const circuit = getRandomCircuit(nodes, 3);

    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");

    let messageToUser = message

    for (let i = circuit.length - 1; i >= 0; i--) {

      const symmectricKey = await createRandomSymmetricKey();
      const symmectricKeyExported = await exportSymKey(symmectricKey);

      const encryptedMessage = await symEncrypt(symmectricKey,`${destination}${messageToUser}`);
      destination = `${BASE_ONION_ROUTER_PORT + circuit[i].nodeId}`.padStart(10, "0");

      const encryptedSymmectricKey = await rsaEncrypt(symmectricKeyExported,circuit[i].pubKey);
      messageToUser = `${encryptedSymmectricKey}${encryptedMessage}`;

    }

    

    lastSentMessage = messageToUser;
    circuit.reverse();

    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: messageToUser })});

    res.status(200).json({ result: "success" });


    




  });

  

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}