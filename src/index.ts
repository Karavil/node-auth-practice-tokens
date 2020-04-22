import { PrismaClient } from "@prisma/client";
import * as bodyParser from "body-parser";
import express from "express";

const prisma = new PrismaClient();
const app = express();

app.use(bodyParser.json());

app.post(`/resources`, async (req, res) => {
   const result = await prisma.resource.create({
      data: {
         ...req.body,
      },
   });
   res.json(result);
});

app.post(`/projects`, async (req, res) => {
   const result = await prisma.project.create({
      data: {
         ...req.body,
      },
   });
   res.json(result);
});

app.post(`/projects/:id/tasks`, async (req, res) => {
   const { id } = req.params;
   const result = await prisma.task.create({
      data: {
         ...req.body,
         project: {
            connect: { id: Number(id) },
         },
      },
   });
   res.json(result);
});

app.delete(`/project/:id`, async (req, res) => {
   const { id } = req.params;
   const result = await prisma.project.delete({
      where: {
         id: Number(id),
      },
   });
   res.status(200).json(result);
});

app.get(`/projects/:id`, async (req, res) => {
   const { id } = req.params;
   const project = await prisma.project.findOne({
      where: {
         id: Number(id),
      },
      include: { resources: true, tasks: true },
   });
   res.status(200).json(project);
});

app.get("/projects", async (req, res) => {
   const projects = await prisma.project.findMany();
   res.status(200).json(projects);
});

app.get("/resources", async (req, res) => {
   const resources = await prisma.resource.findMany();
   res.status(200).json(resources);
});

const server = app.listen(5000, () =>
   console.log("🚀 Server ready at: http://localhost:5000\n")
);
