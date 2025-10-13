
from rest_framework.views import exception_handler


def trendify_exception_handler(exc, context):
    '''
    Wrap every DRF error in this custom exception handler
    '''

    response = exception_handler(exc, context)

    if response is None:
        return response
    
    response.data = {
        "isSuccess": False,
        "data": None,
        "error": response.data,
        "message": None,
    }

    return response
