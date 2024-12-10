import createHttpError from "http-errors";
import bcrypt from "bcrypt";
import { type LoginResponse, type LoginDTO, type RegisterDTO, type RefreshDTO } from "../schemas/auth.schema";
import { prisma } from "../prisma";
import { createAccessToken, createRefreshToken, decodeRefreshToken } from "../services/jwt.service";

export async function login({ username, password }: LoginDTO): Promise<LoginResponse> {
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

  return {
    accessToken,
    refreshToken,
    userId: user.id,
  };
}

export async function register({ username, password }: RegisterDTO): Promise<LoginResponse> {
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

  return {
    accessToken,
    refreshToken,
    userId: user.id,
  };
}

export async function refresh({ refreshToken }: RefreshDTO): Promise<LoginResponse> {
  const { userId } = decodeRefreshToken(refreshToken);

  const accessToken = createAccessToken({ userId });
  const newRefreshToken = createRefreshToken({ userId });

  return {
    accessToken,
    refreshToken: newRefreshToken,
    userId,
  };
}
