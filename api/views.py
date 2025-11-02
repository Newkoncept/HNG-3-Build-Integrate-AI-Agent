import logging, json
from rest_framework.views import APIView
from rest_framework.response import Response

logger = logging.getLogger("a2a")

class HomeAPIView(APIView):

    def post(self, request, *args, **kwargs):

        raw = request.body.decode("utf-8", errors="replace")
        logger.info("📩 Incoming Telex Request:\nHeaders=%s\nBody=%s",
                    dict(request.headers), raw)
        return Response(
            {
                "a" : "Welcome",
                "b" : request.data,
                "c" : request.query_params,
            }
            
            )
