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
  

  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let getLastCircuit: Node[] = [];

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastCircuit", (req, res) => {
   
    res.status(200).json({ result: getLastCircuit.map((node) => node.nodeId) });
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
   
    const { message, destinationUserId } = req.body;
    const registryResponse = await fetch("http://localhost:" + REGISTRY_PORT + "/getNodeRegistry");
    const {nodes} = await registryResponse.json() as {nodes : Node[]};

    let circuit = getRandomCircuit(nodes, 3);
    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");
    let finalMessage = message;


    for (let i = 0; i < circuit.length; i++) {
      const node = circuit[i];
    
      const symmetricKey = await createRandomSymmetricKey();
      const symmetricKey64 = await exportSymKey(symmetricKey);

      const encryptedMessage = await symEncrypt(symmetricKey, `${destination}${finalMessage}`);
    
      destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, '0');
    
      const encryptedSymKey = await rsaEncrypt(symmetricKey64, node.pubKey);
    
      finalMessage = encryptedSymKey + encryptedMessage;
    
    
      console.log(`Node at index ${i}:`, node.nodeId, "Destination:", destination);
    }

    //throw new Error("Circuit1 : " + circuit[0] + "Circuit2 : " + circuit[1] + "Circuit3 : " + circuit[2]);

  
    circuit.reverse();
    getLastCircuit = circuit;
    lastSentMessage = message;
    
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {method: "POST", headers: {"Content-Type": "application/json",},body: JSON.stringify({ message: finalMessage })});


    res.status(200).send("Message sent successfully");
  });

  

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}