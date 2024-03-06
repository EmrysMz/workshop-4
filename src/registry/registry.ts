import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string; privKey?:string };


export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const registry = express();
  registry.use(express.json());
  registry.use(bodyParser.json());

  let nodes: Node[] = [];

  registry.get("/status", (req, res) => {
    res.send("live");
  });

  registry.post("/registerNode", (req, res) => {
    const body = req.body as RegisterNodeBody;
    if (nodes.some((node) => node.nodeId === body.nodeId)) {
      res.status(400).json({ error: "Node already registered" });
    } else {
      
      nodes.push(body);
      res.status(201).json({ result: "Node registered" });
    }
  });

  registry.get("/getNodeRegistry", (req, res) => {
    const response: GetNodeRegistryBody = { nodes };
   
    res.json(response);
  });

  registry.get("/getPrivateKey/:nodeId", (req, res) => {
    const nodeId = Number(req.params.nodeId);
    const node = nodes.find((n) => n.nodeId === nodeId);
    if (node && node.privKey) {
      res.json({ result: node.privKey });
    } else {
      res.status(404).json({ error: "Private key not found for the requested node" });
    }
  });

  const server = registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}