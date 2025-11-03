import logging, json
from rest_framework.views import APIView
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from .utils import randomUUID, get_latest_timestamp, online_data_grabber, filter_last_5_years_from_back, to_telex_parts, validate_JSON_rpc_request, validate_server_error, get_user_request
from rest_framework import status


class HomeAPIView(APIView):

    def post(self, request, *args, **kwargs):
        request_object = request.data

        try:
            json_validator = validate_JSON_rpc_request(request_object)

            if json_validator.get("error", {}):
                return Response(
                    data={
                        "jsonrpc": "2.0",
                        "id": request_object.get("id"),
                        "error": {
                            "code": -32600,
                            "message": "Invalid Request: jsonrpc is required"
                        }
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )


            
            user_request = get_user_request(request_object)

            if user_request is None:
                return Response(
                    data={
                        "jsonrpc": "2.0",
                        "id": request_object.get("id"),
                        "error": {
                            "code": -32600,
                            "message": "User input is required"
                        }
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            

            data_result = online_data_grabber(user_request)
            # print(data_result)
            # print(user_request)

            if data_result is None:
                return Response(
                    data={
                        "jsonrpc": "2.0",
                        "id": request_object.get("id"),
                        "error": {
                            "code": -32000,
                            "message": f"{data_result[1]}"
                        }
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE
                )
            
            if data_result.get("totalResults", {}) == 0:
                return Response(
                    data={
                        "jsonrpc": "2.0",
                        "id": request_object.get("id"),
                        "error": {
                            "code": -32602,
                            "message": f"Result not found"
                        }
                    },
                    status=status.HTTP_404_NOT_FOUND
                )
            

            filtered_result = filter_last_5_years_from_back(data_result)

            if len(filtered_result) < 1:
                return Response(
                    data={
                        "jsonrpc": "2.0",
                        "id": request_object.get("id"),
                        "error": {
                            "code": -32602,
                            "message": f"Result for {user_request} not found"
                        }
                    },
                    status=status.HTTP_404_NOT_FOUND
                )


            result_id = randomUUID()
            context_Id = randomUUID()
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
                            "parts": agent_response
                        }
                    ],
                    "history": [],
                    "kind": 'task'
                }   
            }



            return Response(data, status=status.HTTP_200_OK)


        except Exception as e:
            return validate_server_error(request_object, e)



