from __future__ import annotations

import asyncio
import json
import gzip
from typing import AsyncIterator

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

app = FastAPI(title="ATO deterministic test server")


@app.get("/test")
async def test() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/echo")
async def echo(request: Request) -> PlainTextResponse:
    return PlainTextResponse(await request.body())


@app.post("/json")
async def json_body(body: dict) -> JSONResponse:
    return JSONResponse({"received": body})


@app.post("/binary")
async def binary(request: Request) -> PlainTextResponse:
    return PlainTextResponse(str(len(await request.body())))


@app.get("/gzip")
async def compressed() -> Response:
    return Response(gzip.compress(b'{"compressed":true}'), media_type="application/json",
                    headers={"Content-Encoding": "gzip"})


@app.get("/large")
async def large(size: int = 4096) -> Response:
    return Response(b"x" * min(max(size, 0), 1024 * 1024), media_type="application/octet-stream")


async def events(delay: float = 0.02) -> AsyncIterator[bytes]:
    for index in range(3):
        yield f"event: delta\nid: {index}\ndata: chunk-{index}\n\n".encode()
        await asyncio.sleep(delay)


@app.get("/stream")
async def stream(delay: float = 0.02) -> StreamingResponse:
    return StreamingResponse(events(min(max(delay, 0), 1)), media_type="text/event-stream")


@app.get("/slow")
async def slow() -> PlainTextResponse:
    await asyncio.sleep(0.1)
    return PlainTextResponse("slow")


@app.get("/error")
async def error() -> JSONResponse:
    return JSONResponse({"error": "controlled"}, status_code=418)


@app.websocket("/websocket")
async def websocket_endpoint(socket: WebSocket) -> None:
    await socket.accept()
    while True:
        message = await socket.receive_text()
        await socket.send_text(f"echo:{message}")
