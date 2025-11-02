from rest_framework.views import APIView
from rest_framework.response import Response


class HomeAPIView(APIView):

    def post(self, request, *args, **kwargs):
        return Response(
            {
                "a" : "Welcome",
                "b" : request.data,
                "c" : request.query_params,
            }
            
            )
