import logging, json
from rest_framework.views import APIView
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from .utils import randomUUID, get_latest_timestamp

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

        result_id = randomUUID()
        context_Id = randomUUID()
        agent_response = "A command injection vulnerability in the TP-Link Archer C50 allows remote attackers to execute arbitrary code via the web management interface." 

        data = {
            "jsonrpc": '2.0',
            "id": request.data["id"],
            "result": {
                "id": result_id,
                "contextId": context_Id,
                "status": 
                {
                    "state": 'completed',
                    "timestamp": get_latest_timestamp(),
                    "message": {
                        "messageId": randomUUID(),
                        "role": 'agent',
                        "parts": 
                            [
                                { 
                                    "kind": 'text', 
                                    "text": agent_response,
                                }
                            ],
                        "kind": 'message',
                        "taskId": randomUUID()
                    }
                },
                
                "artifacts":
                [
                    {
                        "artifactId": randomUUID(),
                        "name": 'deviceShield',
                        "parts": [
                            {
                            "kind": "text",
                            "text": agent_response,
                            }
                        ]
                    }
                ],
                "history": [],
                "kind": 'task'
            }   
        }


        return Response(
            data
        )







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
