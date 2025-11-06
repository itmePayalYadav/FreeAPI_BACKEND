from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

class HealthCheckView(APIView):
    """
    Simple health check endpoint.
    Returns 200 OK if the server is running.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"status": "ok", "message": "API is running"}, status=status.HTTP_200_OK)
