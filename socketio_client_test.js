const { io } = require("socket.io-client");

const socket = io("http://127.0.0.1:8090", {
  path: "/socket.io/",
  transports: ["polling", "websocket"],
});

socket.on("connect", () => {
  console.log("connected", socket.id);
  socket.emit("message", { hello: "world" });
  const buf = Buffer.from("bin-test");
  socket.emit("binary", buf);
});

socket.on("welcome", (payload) => {
  console.log("welcome", payload);
});

socket.on("message", (payload) => {
  console.log("message", payload);
  socket.disconnect();
});

socket.on("binary", (payload) => {
  const asString = Buffer.isBuffer(payload) ? payload.toString("utf8") : String(payload);
  console.log("binary", asString);
});

socket.on("disconnect", (reason) => {
  console.log("disconnect", reason);
  process.exit(0);
});

socket.on("connect_error", (err) => {
  console.error("connect_error", err.message);
  process.exit(1);
});
