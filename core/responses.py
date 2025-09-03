from rest_framework.response import Response
from rest_framework import status
from typing import Any, Optional


class TrendifyResponse:
    """
    Standardized response format for all API endpoints

    {
        "isSuccess": boolean,
        "data": any,
        "error": str, only has value if error
        "message": str optional value even if error or success more for developers to read
    }
    """
    
    @staticmethod
    def success(
        data: Any = None,
        message: Optional[str] = None,
        status_code: int = status.HTTP_200_OK
    ) -> Response:
        """
        Return a successful response
        
        Args:
            data: Response data (dict, list, or any serializable object)
            message: Optional success message
            status_code: HTTP status code (default: 200)
        """
        response_data = {
            "isSuccess": True,
            "data": data,
            "error": None,
            "message": message
        }
        return Response(response_data, status=status_code)
    
    @staticmethod
    def error(
        error: str,
        data: Any = None,
        message: Optional[str] = None,
        status_code: int = status.HTTP_400_BAD_REQUEST
    ) -> Response:
        """
        Return an error response
        
        Args:
            error: Error message
            data: Optional data to include
            message: Optional additional message
            status_code: HTTP status code (default: 400)
        """
        response_data = {
            "isSuccess": False,
            "data": data,
            "error": error,
            "message": message
        }
        return Response(response_data, status=status_code)
