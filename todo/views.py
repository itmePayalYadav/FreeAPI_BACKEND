from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from todo.models import Todo
from todo.serializers import (
    TodoSerializer,
    TodoCreateSerializer,
    TodoUpdateSerializer,
    TodoPartialUpdateSerializer,
    TodoSoftDeleteResponseSerializer,
    TodoRestoreResponseSerializer,
    ToggleStatusResponseSerializer,
)
from core.utils import api_response
from core.logger import get_logger
from core.throttles import FreeUserThrottle

# =============================================================
# Logger
# =============================================================
logger = get_logger(__name__)

# =============================================================
# TODO VIEWSET
# =============================================================
class TodoViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [FreeUserThrottle]

    filterset_fields = ["completed", "priority"]
    search_fields = ["title", "description"]
    ordering_fields = ["created_at", "updated_at", "priority"]
    ordering = ["-created_at"]

    # =============================================================
    # Querysets
    # =============================================================
    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Todo.objects.none()
        return Todo.objects.filter(owner=self.request.user, deleted_at__isnull=True)

    def get_deleted_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Todo.all_objects.none()
        return Todo.all_objects.filter(owner=self.request.user, deleted_at__isnull=False)

    # =============================================================
    # Dynamic Serializer
    # =============================================================
    def get_serializer_class(self):
        return {
            "list": TodoSerializer,
            "retrieve": TodoSerializer,
            "create": TodoCreateSerializer,
            "update": TodoUpdateSerializer,
            "partial_update": TodoPartialUpdateSerializer,
        }.get(self.action, TodoSerializer)
        
    # =============================================================
    # RETRIEVE
    # =============================================================
    def retrieve(self, request, *args, **kwargs):
        todo = self.get_object()
        serializer = self.get_serializer(todo)
        return api_response(
            success=True,
            message="Todo retrieved successfully",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )

    # =============================================================
    # CREATE
    # =============================================================
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        todo = serializer.save(owner=request.user)
        logger.info(f"Todo created: {todo.id} by user {request.user.id}")
        response_data = TodoSerializer(todo).data
        return api_response(
            True,
            "Todo created successfully",
            response_data,
            status.HTTP_201_CREATED
        )

    # =============================================================
    # UPDATE
    # =============================================================
    @transaction.atomic
    def update(self, request, *args, **kwargs):
        todo = self.get_object()
        serializer = self.get_serializer(todo, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        logger.info(f"Todo updated: {todo.id} by user {request.user.id}")
        response_data = TodoSerializer(todo).data
        return api_response(
            True,
            "Todo updated successfully",
            response_data,
            status.HTTP_200_OK
        )

    # =============================================================
    # PARTIAL UPDATE
    # =============================================================
    @transaction.atomic
    def partial_update(self, request, *args, **kwargs):
        todo = self.get_object()
        serializer = self.get_serializer(todo, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        logger.info(f"Todo partially updated: {todo.id} by user {request.user.id}")
        response_data = TodoSerializer(todo).data
        return api_response(
            True,
            "Todo partially updated successfully",
            response_data,
            status.HTTP_200_OK
        )

    # =============================================================
    # SOFT DELETE
    # =============================================================
    @action(detail=True, methods=["delete"], url_path="delete")
    @transaction.atomic
    def soft_delete(self, request, pk=None):
        todo = get_object_or_404(self.get_queryset(), id=pk)
        todo.soft_delete()
        logger.info(f"Todo soft-deleted: {todo.id} by user {request.user.id}")
        response_data = TodoSoftDeleteResponseSerializer({
            "id": todo.id,
            "message": "Todo deleted successfully",
        }).data
        return api_response(
            True,
            "Todo deleted successfully",
            response_data,
            status.HTTP_200_OK
        )

    # =============================================================
    # RESTORE
    # =============================================================
    @action(detail=True, methods=["post"], url_path="restore")
    @transaction.atomic
    def restore(self, request, pk=None):
        todo = get_object_or_404(self.get_deleted_queryset(), id=pk)
        todo.restore()
        logger.info(f"Todo restored: {todo.id} by user {request.user.id}")
        response_data = TodoRestoreResponseSerializer({
            "id": todo.id,
            "message": "Todo restored successfully",
        }).data
        return api_response(
            True,
            "Todo restored successfully",
            response_data,
            status.HTTP_200_OK
        )

    # =============================================================
    # TOGGLE STATUS
    # =============================================================
    @action(detail=True, methods=["patch"], url_path="toggle-status")
    @transaction.atomic
    def toggle_status(self, request, pk=None):
        todo = get_object_or_404(self.get_queryset(), id=pk)
        todo.completed = not todo.completed
        todo.updated_at = timezone.now()
        todo.save(update_fields=["completed", "updated_at"])
        logger.info(f"Todo status toggled: {todo.id} by user {request.user.id} to {todo.completed}")
        response_data = ToggleStatusResponseSerializer({
            "id": todo.id,
            "completed": todo.completed,
        }).data
        return api_response(
            True,
            "Todo status toggled successfully",
            response_data,
            status.HTTP_200_OK
        )
