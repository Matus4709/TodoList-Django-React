from django.conf import settings
import jwt, datetime
from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import UserSerializer, TaskSerializer
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .models import User, Tasks

def get_user_from_token(request):
    token = request.COOKIES.get('jwt')
    if not token:
        raise AuthenticationFailed("Unauthenticated!")

    try:
        payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        user = User.objects.get(id=payload['id'])
        return user
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Token has expired!")
    except jwt.InvalidTokenError:
        raise AuthenticationFailed("Invalid token!")
    except User.DoesNotExist:
        raise AuthenticationFailed("User not found!")

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed("User not found!")
        if not user.check_password(password):
            raise AuthenticationFailed("Incorrect password!")
        
        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow(),
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')


        response =  Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }

        return response

class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')
        
        if not token:
            raise AuthenticationFailed("Unautheticated!")
        try:
            payload = jwt.decode(token,'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unautheticated!")
        
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)

        return Response(serializer.data)
    
class LogoutView(APIView):
    def post(self, request):
        response =  Response()
        response.delete_cookie('jwt')
        response.data = {
            "message": "success",
        }
        return response

class TaskListCreate(APIView):
    def get(self, request):
        request.user = get_user_from_token(request)
        tasks = Tasks.objects.filter(user=request.user)
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)

    def post(self, request):
        request.user = get_user_from_token(request)
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TaskDetail(APIView):
    
    def get_task(self, pk, user):
        task = Tasks.objects.get(pk=pk, user=user)
        if task:
            return task
        else: 
            return Response(status=status.HTTP_404_NOT_FOUND)
    
    def get(self, request, pk):
        user = get_user_from_token(request)
        task = self.get_task(pk, user)
        serializer = TaskSerializer(task)
        return Response(serializer.data)
    
    def put(self, request, pk):
        user = get_user_from_token(request)
        task = self.get_task(pk, user)
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        user = get_user_from_token(request)
        task = self.get_task(pk, user)
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    def patch(self, request,pk):
        user = get_user_from_token(request)
        task = self.get_task(pk, user)
        serializer = TaskSerializer(task, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)