# myapp/middleware.py
from user_agents import parse

class DeviceDetectionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ua_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse(ua_string)

        request.is_mobile = user_agent.is_mobile
        request.is_tablet = user_agent.is_tablet
        request.is_touch = user_agent.is_touch_capable
        request.is_pc = user_agent.is_pc
        return self.get_response(request)

