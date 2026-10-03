from django.urls import path

from . import views

app_name = "q_bank"

urlpatterns = [
    path("", views.dashboard_view, name="dashboard"),
    path("person/create/", views.create_person_view, name="create_person"),
    path("person/<uuid:person_id>/", views.person_detail_view, name="person_detail"),
    path("person/<uuid:person_id>/delete/", views.delete_person_view, name="delete_person"),
    path("account/<uuid:account_id>/", views.account_detail_view, name="account_detail"),
    path("account/<uuid:account_id>/delete/", views.delete_account_view, name="delete_account"),
    path("upload/", views.upload_statement_view, name="upload_statement"),
    path("api/transactions/", views.transactions_api_view, name="transactions_api"),
    path("api/fuzzy-search/", views.fuzzy_search_api_view, name="fuzzy_search_api"),
    path("api/parse-keywords/", views.parse_keywords_api_view, name="parse_keywords_api"),
    path("export/ledger/", views.export_ledger_excel_view, name="export_ledger_excel"),
    path("export/frequent/", views.export_frequent_excel_view, name="export_frequent_excel"),
]
