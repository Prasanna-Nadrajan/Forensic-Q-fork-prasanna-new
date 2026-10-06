from django.urls import path

from . import views

app_name = "q_verify"

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("case/create/", views.create_case_api_view, name="case_create"),
    path("case/<uuid:case_id>/", views.case_detail_view, name="case_detail"),
    path("case/<uuid:case_id>/upload/", views.upload_documents_api_view, name="case_upload"),
    path(
        "case/<uuid:case_id>/documents/",
        views.documents_grid_api_view,
        name="documents_grid_api",
    ),
    path("quick-scan/", views.quick_scan_api_view, name="quick_scan"),
    path("document/<uuid:doc_id>/", views.document_detail_api_view, name="document_detail"),
    path(
        "document/<uuid:doc_id>/download/",
        views.download_document_view,
        name="document_download",
    ),
    path(
        "document/<uuid:doc_id>/search/",
        views.document_search_api_view,
        name="document_search",
    ),
]
