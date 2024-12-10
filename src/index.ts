import express from "express";
import dotenv from "dotenv-safe";
import helmet from "helmet";
import cors from "cors";
import "express-async-errors";

import { prisma } from "./prisma";

import { handleZodError } from "./middlewares/handleZodError.middleware";
import { handlePrismaError } from "./middlewares/handlePrismaError.middleware";
import { handleCommonError } from "./middlewares/handleCommonError.middleware";

import todoRoute from "./routes/todo.route";
import authRoute from "./routes/auth.route";
import { requireLogin } from "./middlewares/auth.middleware";

dotenv.config();

const app = express();

app.use(express.json());
app.use(cors());
app.use(helmet());

// Include your routes here
app.use("/auth", authRoute);
app.use("/todo", requireLogin, todoRoute);

app.use(handleZodError);
app.use(handlePrismaError);
app.use(handleCommonError);

const PORT = process.env.PORT ?? 8080;

app.listen(PORT, async () => {
  await prisma.$connect();
  console.log(`Server started on http://localhost:${PORT}`);
});
