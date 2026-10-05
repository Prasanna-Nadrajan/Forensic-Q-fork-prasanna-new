from django.urls import path

from . import views

urlpatterns = [
    path("", views.landing_view, name="landing"),
    path("login/", views.portal_login_view, name="portal_login"),
    path("logout/", views.portal_logout_view, name="portal_logout"),
    path("profiles/create/", views.create_profile_view, name="create_profile"),
    path(
        "profiles/<uuid:profile_id>/keywords/",
        views.add_profile_keywords_view,
        name="add_profile_keywords",
    ),
    path(
        "profiles/<uuid:profile_id>/keywords/upload/",
        views.upload_profile_keywords_file_view,
        name="upload_profile_keywords_file",
    ),
    path(
        "api/keywords/parse-file/",
        views.parse_keywords_file_view,
        name="parse_keywords_file",
    ),
    path("profiles/active/", views.set_active_profile_view, name="set_active_profile"),
    path("api/profiles/", views.profile_list_api_view, name="api_profiles"),
    path("audits/create/", views.create_audit_view, name="create_audit"),
    path(
        "audits/<uuid:audit_id>/map-profiles/",
        views.map_audit_profiles_view,
        name="map_audit_profiles",
    ),
    path("audits/active/", views.set_active_audit_view, name="set_active_audit"),
    path("api/audits/", views.audit_list_api_view, name="api_audits"),
    path("api/audits/next-name/", views.get_next_audit_name_api_view, name="api_next_audit_name"),
]
