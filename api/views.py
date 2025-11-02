import logging, json
from rest_framework.views import APIView
from rest_framework.response import Response

logger = logging.getLogger("a2a")

class HomeAPIView(APIView):

    def post(self, request, *args, **kwargs):

        raw = request.body.decode("utf-8", errors="replace")

        try:
            parsed = json.loads(raw)
            formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
            logger.info("📩 Incoming Telex Request (formatted):\n%s", formatted)
        except Exception:
            logger.info("📩 Incoming Telex Request (raw): %s", raw)

            
        return Response(
            {
                "a" : "Welcome",
                "b" : request.data,
                "c" : request.query_params,
            }
            
            )
