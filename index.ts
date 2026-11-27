import { createVmQueueApp } from "./server.ts";

const host = process.env.VM_QUEUE_HOST ?? "127.0.0.1";
if (host !== "127.0.0.1" && host !== "::1") {
  console.error("VM_QUEUE_HOST must be a loopback address (127.0.0.1 or ::1)");
  process.exit(1);
}

const rawPort = process.env.VM_QUEUE_PORT ?? "8790";
const port = Number(rawPort);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("VM_QUEUE_PORT must be an integer between 1 and 65535");
  process.exit(1);
}

const adminToken = process.env.VM_QUEUE_ADMIN_TOKEN ?? "";
const workerToken = process.env.VM_QUEUE_WORKER_TOKEN ?? "";
if (adminToken.length < 24 || workerToken.length < 24) {
  console.error("VM_QUEUE_ADMIN_TOKEN and VM_QUEUE_WORKER_TOKEN must each be at least 24 characters");
  process.exit(1);
}
if (adminToken === workerToken) {
  console.error("VM_QUEUE_ADMIN_TOKEN and VM_QUEUE_WORKER_TOKEN must be distinct");
  process.exit(1);
}

const dbPath =
  process.env.VM_QUEUE_DB_PATH ?? "/home/ubuntu/services/vm-queue/data/vm-queue.db";

const app = createVmQueueApp({
  dbPath,
  adminToken,
  workerToken,
  host,
  port,
  onAuthFailure: (info) => {
    console.warn(
      JSON.stringify({
        ts: new Date().toISOString(),
        event: "auth_failed",
        ...info,
      }),
    );
  },
});

console.log(`vm-queue listening on http://${host}:${app.server.port}`);

const shutdown = () => {
  app.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
