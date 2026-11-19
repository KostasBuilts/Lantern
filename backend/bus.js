// Tiny in-process pub/sub for Server-Sent Events (live alert + event feed).
const clients = new Set();

export function addClient(res) {
  clients.add(res);
  res.on("close", () => clients.delete(res));
}

export function publish(type, data) {
  const frame = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) {
    try { res.write(frame); } catch { clients.delete(res); }
  }
}

export function clientCount() { return clients.size; }
