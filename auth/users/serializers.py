from rest_framework import serializers
from .models import User, Tasks

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'name', 'email', 'password','date_joined')
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class TaskSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", help_text="Creation time")
    updated_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", help_text="Last update time")
    
    class Meta:
        model = Tasks
        fields = ['id', 'title', 'description', 'completed', 'created_at', 'updated_at', 'user']
        read_only_fields = ['id', 'created_at', 'user']