import { Router } from "express";
import { LoginSchema, RefreshSchema, RegisterSchema } from "../schemas/auth.schema";
import { prisma } from "../prisma";
import createHttpError from "http-errors";
import bcrypt from "bcrypt";
import { createAccessToken, createRefreshToken, decodeRefreshToken } from "../services/jwt.service";

const router = Router();

router.post("/login", async (req, res) => {
  // Validate input
  const { username, password } = LoginSchema.parse(req.body);

  // Execute business logic
  const user = await prisma.user.findUnique({
    where: {
      username,
    },
    select: {
      id: true,
      password: true,
    },
  });

  if (user === null) {
    throw new createHttpError.Unauthorized("Nome de usuário ou senha incorretos");
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw new createHttpError.Unauthorized("Nome de usuário ou senha incorretos");
  }

  const accessToken = createAccessToken({ userId: user.id });
  const refreshToken = createRefreshToken({ userId: user.id });

  // Send response
  return res.status(200).json({
    accessToken,
    refreshToken,
    userId: user.id,
  });
});

router.post("/register", async (req, res) => {
  // Validate input
  const { username, password } = RegisterSchema.parse(req.body);

  // Execute business logic
  const hash = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      username,
      password: hash,
    },
    select: {
      id: true,
    },
  });

  const accessToken = createAccessToken({ userId: user.id });
  const refreshToken = createRefreshToken({ userId: user.id });

  // Send response
  return res.status(201).json({
    accessToken,
    refreshToken,
    userId: user.id,
  });
});

router.post("/refresh", async (req, res) => {
  // Validate input
  const { refreshToken } = RefreshSchema.parse(req.body);

  // Execute business logic
  const { userId } = decodeRefreshToken(refreshToken);

  const accessToken = createAccessToken({ userId });
  const newRefreshToken = createRefreshToken({ userId });

  // Send response
  return res.status(200).json({
    accessToken,
    refreshToken: newRefreshToken,
    userId,
  });
});

export default router;
