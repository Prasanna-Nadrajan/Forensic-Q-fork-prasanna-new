from django.urls import path

from .views import (
    api_acknowledge_alert,
    api_copilot_chat,
    api_edge_detail,
    api_entity_detail,
    api_network_data,
    api_sync_modules,
    dashboard_view,
)

app_name = "q_link"

urlpatterns = [
    path("", dashboard_view, name="dashboard"),
    path("api/network/", api_network_data, name="api_network"),
    path("api/edge/<str:edge_id>/", api_edge_detail, name="api_edge_detail"),
    path("api/entity/<str:entity_id>/", api_entity_detail, name="api_entity_detail"),
    path("api/copilot/", api_copilot_chat, name="api_copilot_chat"),
    path("api/sync/", api_sync_modules, name="api_sync_modules"),
    path("api/alert/<str:alert_id>/ack/", api_acknowledge_alert, name="api_ack_alert"),
]
