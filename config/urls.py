from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),

    # API Schema & Docs
    path("api/v1/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/v1/docs/swagger/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/v1/docs/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),

    # Apps
    path("api/v1/accounts/", include(("accounts.urls", "accounts"), namespace="accounts")),
    path("api/v1/todo/", include(("todo.urls", "todo"), namespace="todo")),
    path("api/v1/social/", include(("social.urls", "social"), namespace="social")),
    path("api/v1/shop/", include(("shop.urls", "shop"), namespace="shop")),
    path("api/v1/chats/", include(("chat.urls", "chat"), namespace="chat")),
    path("api/v1/public/", include(("public.urls", "public"), namespace="public")),
    path("api/v1/kitchen/", include(("kitchen.urls", "kitchen"), namespace="kitchen")),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
