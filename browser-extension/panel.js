import {GATEWAY, BODY_LIMIT, makeObservation, readResponseContent} from "./capture.mjs";

const $ = id => document.getElementById(id);
let running = false, saved = 0, dropped = 0, generation = 0, reading = 0;
let key = "", limit = BODY_LIMIT, sending = false;
const queue = [];
const MAX_PENDING = 25;

function status(message) {
  $("status").textContent = message;
  $("counts").textContent = `Saved: ${saved} · Dropped: ${dropped}`;
  $("start").disabled = running;
  $("stop").disabled = !running;
}

async function post(path, value) {
  const response = await fetch(GATEWAY + path, {method: "POST", credentials: "omit", cache: "no-store",
    headers: {"Content-Type": "application/json", "X-ATO-Pairing-Key": key},
    body: JSON.stringify(value), signal: AbortSignal.timeout(7000)});
  if (!response.ok) throw new Error(response.status === 403 ? "Pairing rejected. Copy the current key from the viewer." :
    `Gateway returned ${response.status}. Check the observer is running.`);
  return response.json();
}

async function flush() {
  if (sending || !running) return;
  sending = true;
  const cycle = generation;
  try {
    while (running && generation === cycle && queue.length) {
      await post("/api/browser/flows", queue[0]);
      if (!running || generation !== cycle) break;
      queue.shift();
      saved++;
      status("Recording this tab. Reload it to include initial requests.");
    }
  } catch (error) {
    if (running && generation === cycle) {
      running = false;
      generation++;
      dropped += queue.length;
      queue.length = 0;
      status(`Recording stopped: ${error.message}`);
    }
  } finally { sending = false; if (running && queue.length) void flush(); }
}

$("start").addEventListener("click", async () => {
  key = $("pairing").value.trim();
  if (!key) { status("Paste the current pairing key from the local viewer."); return; }
  $("start").disabled = true;
  try {
    const setup = await post("/api/browser/connect", {});
    limit = Math.min(BODY_LIMIT, setup.max_body_bytes);
    running = true;
    generation++;
    status("Recording this tab. Reload it to include initial requests.");
  } catch (error) { status(`Could not connect: ${error.message}`); }
});

$("stop").addEventListener("click", () => {
  running = false;
  generation++;
  dropped += queue.length;
  queue.length = 0;
  status("Stopped. Already saved observations remain in the local viewer.");
});

chrome.devtools.network.onRequestFinished.addListener(async request => {
  if (!running) return;
  if (queue.length + reading >= MAX_PENDING) { dropped++; status("Recording; pending limit reached, some observations dropped."); return; }
  const cycle = generation;
  reading++;
  try {
    const body = await readResponseContent(request);
    if (!running || cycle !== generation) return;
    const observation = makeObservation(request, body.content, body.encoding, chrome.devtools.inspectedWindow.tabId, limit);
    if (!observation) return;
    queue.push(observation);
    void flush();
  } catch {
    dropped++;
    status("Recording; a browser observation could not be collected.");
  } finally { reading--; }
});

status("Not recording.");
