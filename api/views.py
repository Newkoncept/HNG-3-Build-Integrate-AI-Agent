import logging, json
from rest_framework.views import APIView
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt

# from .data import data

# logger = logging.getLogger("a2a")
# @csrf_exempt
class HomeAPIView(APIView):

    def post(self, request, *args, **kwargs):
        # print(request.query_params)
        # print(request.data)
        # print(json.loads(request.data))

        print(request.data["id"])
        # print(self.request.query_params)

        # raw = request.body.decode("utf-8", errors="replace")

        # try:
        #     parsed = json.loads(raw)
        #     formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        #     logger.info("📩 Incoming Telex Request (formatted):\n%s", formatted)
        # except Exception:
        #     logger.info("📩 Incoming Telex Request (raw): %s", raw)

        # print(data)
        # raw = json.loads(data["message"])
        # formatted = json.dumps(raw, indent=2, ensure_ascii=False)
        # raw = request.body.decode("utf-8", errors="replace")
        # logger.info("📩 Incoming Telex Request:\nHeaders=%s\nBody=%s",
        #             dict(request.headers), raw)

        return Response(
            {
          "jsonrpc": '2.0',
          "id": request.data["id"],
          "error": {
            "code": -32600,
            "message": 'Invalid Request: jsonrpc must be "2.0" and id is required'
          }
        }, 400)

        return Response(
            {
                "a" : "Welcome",
                # "b" : request.data,
                # "c" : request.query_params,
                # "format": formatted,
            }
            
            )
