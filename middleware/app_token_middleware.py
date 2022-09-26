from django.http import JsonResponse

from apptoken.model import ApplicationToken


class AppTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        if 'admin_masked_url_hidden' in request.path \
                or '/health/' in request.path\
                or '/verify-email/' in request.path:
            response = self.get_response(request)
        else:
            try:
                # print(request.META.keys())
                if 'HTTP_X_WEB_TOKEN' in request.META:
                    token = request.META['HTTP_X_WEB_TOKEN']
                    db_token = ApplicationToken.objects.get(title='X-WEB-TOKEN')
                    if token == str(db_token.token):
                        response = self.get_response(request)
                    else:
                        return JsonResponse({"status": "Unauthorized", "error": "Invalid token"}, status=401)
                else:
                    return JsonResponse({"status": "Unauthorized", "error": "No Token Provided"}, status=401)
            except:
                return JsonResponse({"status": "Unauthorized", "error": "Unexpected Exception"}, status=401)

        # Code to be executed for each response after the view is called

        return response
