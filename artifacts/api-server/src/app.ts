import express, { type Express } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import { authMiddleware } from "./middlewares/authMiddleware";
import {
  apiLimiter,
  scanLimiter,
  rateLimitErrorHandler,
} from "./middlewares/rateLimitMiddleware.js";
import router from "./routes";
import { logger } from "./lib/logger";

const app: Express = express();
const allowedOrigins = (process.env.CORS_ORIGINS ?? "http://localhost:5173")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

// Trust proxy for production (handles X-Forwarded-For from reverse proxies like Render)
app.set("trust proxy", 1);

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
app.use(
  cors({
    credentials: true,
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Origin not allowed by CORS"));
    },
  }),
);
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(authMiddleware);

// Apply general API rate limiter to all /api routes
app.use("/api/", apiLimiter);

// Apply scan-specific rate limiter to scan endpoints
app.use("/api/scan", scanLimiter);

app.use("/api", router);

// Apply rate limit error handler before other error handlers
app.use(rateLimitErrorHandler);

export default app;
