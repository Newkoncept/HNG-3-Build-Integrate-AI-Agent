import logging, json
from rest_framework.views import APIView
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from .utils import randomUUID, get_latest_timestamp, online_data_grabber, filter_last_5_years_from_back, to_telex_parts

# from .datas import daa

# logger = logging.getLogger("a2a")
# @csrf_exempt
class HomeAPIView(APIView):

    def post(self, request, *args, **kwargs):
        data_result = online_data_grabber("TP-LINK TL-WR841N")
        # data_result = daa["vulnerabilities"][0]
        # data_result1 = daa["vulnerabilities"][1]
        # cve = data_result["cve"]

        filtered_result = filter_last_5_years_from_back(data_result)

        # return Response(
        #     filter_last_5_years_from_back(daa)
        # )


        # print(data_result)

        result_id = randomUUID()
        context_Id = randomUUID()
        # agent_response = "A command injection vulnerability in the TP-Link Archer C50 allows remote attackers to execute arbitrary code via the web management interface." 
        agent_response = to_telex_parts(filtered_result)


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
                        "parts": agent_response,
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
                "history": request.data["params"]["message"],
                "kind": 'task'
            }   
        }


        # return Response(
        #     {
        #         "one": data_result,
        #         "two": data_result1
                
        #     }
        # )

        return Response(data)






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
