from rest_framework.views import APIView
from rest_framework.response import Response
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .utils import online_data_grabber, filter_last_5_years_from_most_recent_vuln, to_telex_parts, validate_JSON_rpc_request, get_user_request, rpc_success, rpc_error, build_error_message
from rest_framework import status
import json
from .models import JSONRPCRequest

@method_decorator(csrf_exempt, name="dispatch")
class HomeAPIView(APIView):

    def post(self, request, *args, **kwargs):

        try:
            body = json.loads(request.body.decode("utf-8"))
        except Exception as e:
            return Response(rpc_error(None, -32700, "Parse error"), status=status.HTTP_400_BAD_REQUEST)
        
        if not isinstance(body, dict):
             return Response(rpc_error(None, -32600, "Invalid Request: JSON must be an object"), status=status.HTTP_400_BAD_REQUEST)
        
        
        request_object = body

        try:
            json_validator = validate_JSON_rpc_request(request_object)

            if json_validator.get("error", {}):
                return Response(rpc_error(None, -32600, json_validator.get("error")), status=status.HTTP_400_BAD_REQUEST)

    
            try:
                request_object_validator = JSONRPCRequest.model_validate(body)
            except Exception as e:
                return Response(rpc_error(None, -32603, str(e)), status=status.HTTP_400_BAD_REQUEST)

            
            user_request = get_user_request(request_object) 
            request_id = request_object.get("id") 
            

            data_result = online_data_grabber(user_request)

            if data_result[0] is None:
                agent_response = build_error_message("Server Error: Unable to provide response to this request at this time.")

                
                return Response(rpc_success(request_id, agent_response), status=status.HTTP_200_OK)
            
                
            if data_result[0].get("totalResults", {}) == 0:
                agent_response = build_error_message(f"No result for your request: {user_request}.")
                return Response(rpc_success(request_id, agent_response), status=status.HTTP_200_OK)
            

            filtered_result = filter_last_5_years_from_most_recent_vuln(data_result[0])

            if len(filtered_result) < 1:
                agent_response = build_error_message(f"No recent vulnerability found for your request: {user_request} in the last 5 years.")
                
                return Response(rpc_success(request_id, agent_response), status=status.HTTP_200_OK)


            
            agent_response = to_telex_parts(user_request, filtered_result)
            data = rpc_success(request_id, agent_response)

            return Response(data, status=status.HTTP_200_OK)


        except Exception as e:
            return Response(rpc_error(None, -32603, "Internal error", str(e)), status=status.HTTP_500_INTERNAL_SERVER_ERROR)



