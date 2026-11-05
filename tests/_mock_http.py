"""An httpx client whose answers come from a mock, for tests written against
``request``.

The SDK streams each answer (see ``willow._body``), so it never calls an
httpx client's ``request``. ``MockHttp`` answers what the SDK sends through
a real ``MockTransport``, from ``request``: set it to an ``AsyncMock``
returning a response mock (``status_code`` and ``json()``) or an
``httpx.Response``, or raising an httpx error. It is called with the
method and URL as its first arguments, and the body and headers as sent.
"""

from unittest.mock import AsyncMock

import httpx


class MockHttp(httpx.AsyncClient):
    def __init__(self):
        super().__init__(transport=httpx.MockTransport(self._answer))
        self.request = AsyncMock()

    async def _answer(self, request: httpx.Request) -> httpx.Response:
        headers = {k.decode(): v.decode() for k, v in request.headers.raw}
        answer = await self.request(
            request.method, str(request.url), content=request.content or None, headers=headers
        )
        if isinstance(answer, httpx.Response):
            return answer
        if answer.json.side_effect is None:
            return httpx.Response(answer.status_code, json=answer.json.return_value)
        return httpx.Response(answer.status_code, text=answer.text)
