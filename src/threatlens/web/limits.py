"""Request body size limits (enforced while streaming, before anything is parsed)."""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Non-upload requests (forms, JSON) never need more than this.
DEFAULT_LIMIT = 1024 * 1024


class BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject bodies over the limit with 413, by Content-Length up front and by
    counting bytes as they arrive (Content-Length can be absent or wrong)."""

    def __init__(self, app: ASGIApp, upload_paths: dict[str, int]) -> None:
        self.app = app
        self.upload_paths = upload_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.upload_paths.get(scope.get("path", ""), DEFAULT_LIMIT)
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > limit:
                        await _reject(send, limit)
                        return
                except ValueError:
                    await _reject(send, limit)
                    return
        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLargeError:
            if not response_started:
                await _reject(send, limit)


async def _reject(send: Send, limit: int) -> None:
    body = f"Request body too large (limit {limit // (1024 * 1024) or 1} MB)".encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
