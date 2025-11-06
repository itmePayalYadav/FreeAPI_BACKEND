from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field
from todo.models import Todo

class TodoSerializer(serializers.ModelSerializer):
    # ----------------------
    # Computed Fields
    # ----------------------
    status = serializers.SerializerMethodField()

    @extend_schema_field(serializers.CharField())
    def get_status(self, obj) -> str:
        return "Completed" if obj.completed else "Pending"

    # ----------------------
    # Meta Configuration
    # ----------------------
    class Meta:
        model = Todo
        fields = [
            "id",
            "title",
            "description",
            "completed",
            "due_date",
            "priority",
            "status",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["status", "created_at", "updated_at"]

# ----------------------
# Response serializer 
# ----------------------
class ToggleStatusResponseSerializer(serializers.Serializer):
    # ----------------------
    # Fields
    # ----------------------
    id = serializers.UUIDField(help_text="Todo ID")
    completed = serializers.BooleanField(help_text="Current completion status")
