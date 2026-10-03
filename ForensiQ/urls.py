from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    path(
        "favicon.ico",
        RedirectView.as_view(url=settings.STATIC_URL + "core/images/favicon.ico", permanent=False),
    ),
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
    path("demo/", include("demo.urls")),
    path("mail/", include("q_mail.urls")),
    path("verify/", include("q_verify.urls")),
    path("scan/", include("q_scan.urls")),
    path("bank/", include("q_bank.urls")),
    path("chat/", include("q_chat.urls")),
    path("ledger/", include("q_ledger.urls")),
    path("voice/", include("q_voice.urls")),
    path("trail/", include("q_trail.urls")),
]

if settings.DEBUG:
    from django.contrib.staticfiles.urls import staticfiles_urlpatterns

    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += staticfiles_urlpatterns()
