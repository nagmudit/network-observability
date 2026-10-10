import test from "node:test";
import assert from "node:assert/strict";
import {captureBody, cleanHeaders, makeObservation, readResponseContent} from "../browser-extension/capture.mjs";

test("captures bounded UTF-8 prefixes and marks truncation", () => {
  const captured = captureBody("hello 🌍", "", 8);
  assert.equal(Buffer.from(captured.base64, "base64").length, 8);
  assert.equal(captured.truncated, true);
  assert.equal(captureBody(undefined).base64, null);
});

test("preserves binary bytes when DevTools returns base64", () => {
  const input = Buffer.from([0, 255, 16, 128, 1]);
  const captured = captureBody(input.toString("base64"), "base64", 4);
  assert.deepEqual(Buffer.from(captured.base64, "base64"), input.subarray(0, 4));
  assert.equal(captured.truncated, true);
});

test("redacts sensitive headers before sending to the local server", () => {
  const headers = cleanHeaders([{name:"Cookie",value:"test-only"},{name:"X-Test",value:"visible"}]);
  assert.deepEqual(headers, [{name:"Cookie",value:"<redacted>"},{name:"X-Test",value:"visible"}]);
});

const entry = {request:{url:"https://example.test/api",method:"POST",headers:[],bodySize:-1,
  postData:{text:'{"prompt":"example"}'}},response:{status:200,headers:[],content:{size:12}},time:20};

test("normalizes HAR observations without claiming unknown sizes", () => {
  const value = makeObservation(entry, "example body", "", 42);
  assert.equal(value.tab_id, 42);
  assert.equal(value.request_reported_size, null);
  assert.equal(Buffer.from(value.request_body_base64,"base64").toString(), entry.request.postData.text);
  assert.equal(makeObservation({...entry,request:{...entry.request,url:"http://127.0.0.1:8765/api/status"}},"", "",42),null);
});

test("supports legacy and Promise-based DevTools body retrieval", async () => {
  const legacy = await readResponseContent({getContent:callback=>callback("text", "")});
  assert.equal(legacy.content,"text");
  const modern = await readResponseContent({getContent:()=>Promise.resolve({content:"binary",encoding:"base64"})});
  assert.equal(modern.encoding,"base64");
});

test("missing browser body resolves without blocking the capture queue", async () => {
  assert.equal((await readResponseContent({getContent:()=>{}}, 5)).content, null);
});
