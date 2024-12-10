import createHttpError from "http-errors";
import jwt, { type JwtPayload } from "jsonwebtoken";

export interface AccessTokenPayload {
  userId: number;
}

export interface RefreshTokenPayload {
  userId: number;
}

export function createAccessToken({ userId }: AccessTokenPayload) {
  const secret = process.env.JWT_SECRET;
  const expiresIn = process.env.JWT_EXPIRES_IN;

  return jwt.sign({ userId }, secret, { expiresIn });
}

export function createRefreshToken({ userId }: RefreshTokenPayload) {
  const secret = process.env.JWT_REFRESH_SECRET;
  const expiresIn = process.env.JWT_REFRESH_EXPIRES_IN;

  return jwt.sign({ userId }, secret, { expiresIn });
}

export function decodeAccessToken(jwtToken: string): AccessTokenPayload {
  try {
    const decodedToken = jwt.verify(jwtToken, process.env.JWT_SECRET) as JwtPayload;

    if (decodedToken.userId === undefined) {
      throw new Error();
    }

    const userId = parseInt(decodedToken.userId, 10);

    if (isNaN(userId)) {
      throw new Error();
    }

    return {
      userId,
    };
  } catch (error) {
    throw new createHttpError.Unauthorized("Token inválido ou expirado");
  }
}

export function decodeRefreshToken(jwtToken: string): RefreshTokenPayload {
  try {
    const decodedToken = jwt.verify(jwtToken, process.env.JWT_REFRESH_SECRET) as JwtPayload;

    if (decodedToken.userId === undefined) {
      throw new Error();
    }

    const userId = parseInt(decodedToken.userId, 10);

    if (isNaN(userId)) {
      throw new Error();
    }

    return {
      userId,
    };
  } catch (error) {
    throw new createHttpError.Unauthorized("Token inválido ou expirado");
  }
}
