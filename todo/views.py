from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import viewsets, permissions, throttling, status
from rest_framework.decorators import action
from drf_spectacular.utils import extend_schema, OpenApiParameter
from todo.models import Todo
from todo.serializers import TodoSerializer, ToggleStatusResponseSerializer
from core.utils import api_response
from core.throttles import FreeAnonThrottle, FreeUserThrottle
from core.permissions import IsSuperAdmin, IsAdminOrSuperAdmin, IsOwnerOrAdmin

# ------------------------------
# Todo ViewSet
# ------------------------------
class TodoViewSet(viewsets.ModelViewSet):
    serializer_class = TodoSerializer
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [FreeUserThrottle]

    filterset_fields = ['completed', 'priority']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'updated_at', 'priority']
    ordering = ['-created_at']

    # ----------------------
    # Querysets
    # ----------------------
    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Todo.objects.none()
        return Todo.objects.filter(owner=self.request.user, deleted_at__isnull=True)

    def get_deleted_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Todo.objects.none()
        return Todo.objects.filter(owner=self.request.user, deleted_at__isnull=False)

    # ----------------------
    # Create
    # ----------------------
    @transaction.atomic
    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    # ----------------------
    # Soft Delete
    # ----------------------
    @extend_schema(parameters=[OpenApiParameter("pk", type=str, location=OpenApiParameter.PATH)])
    @action(detail=True, methods=["delete"], url_path="delete")
    @transaction.atomic
    def soft_delete(self, request, pk=None):
        todo = get_object_or_404(self.get_queryset(), id=pk)
        todo.soft_delete()
        return api_response(True, "Todo deleted successfully", None, status.HTTP_200_OK)

    # ----------------------
    # Restore
    # ----------------------
    @extend_schema(parameters=[OpenApiParameter("pk", type=str, location=OpenApiParameter.PATH)])
    @action(detail=True, methods=["post"], url_path="restore")
    @transaction.atomic
    def restore(self, request, pk=None):
        todo = get_object_or_404(self.get_deleted_queryset(), id=pk)
        todo.restore()
        serializer = TodoSerializer(todo)
        return api_response(True, "Todo restored successfully", serializer.data, status.HTTP_200_OK)

    # ----------------------
    # Toggle Status
    # ----------------------
    @extend_schema(
        parameters=[OpenApiParameter("pk", type=str, location=OpenApiParameter.PATH)],
        responses={200: ToggleStatusResponseSerializer},
    )
    @action(detail=True, methods=["patch"], url_path="toggle-status")
    @transaction.atomic
    def toggle_status(self, request, pk=None):
        todo = get_object_or_404(self.get_queryset(), id=pk)
        todo.completed = not todo.completed
        todo.updated_at = timezone.now()
        todo.save(update_fields=["completed", "updated_at"])

        serializer = ToggleStatusResponseSerializer({
            "id": todo.id,
            "completed": todo.completed
        })
        return api_response(True, "Todo status toggled", serializer.data, status.HTTP_200_OK)
