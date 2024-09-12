from django.conf import settings
import jwt, datetime
from django.shortcuts import render, get_object_or_404
from rest_framework.views import APIView
from .serializers import UserSerializer, TaskSerializer, PasswordResetSerializer
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .models import User, Tasks
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model

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
        user = serializer.save()

         # Generowanie linku aktywacyjnego
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_link = request.build_absolute_uri(f'/api/activate/{uid}/{token}/')

         # Wysyłanie e-maila
        subject = 'Activate your account'
        message = render_to_string('activate_email.html', {
            'user': user,
            'activation_link': activation_link,
        })
        send_mail(subject, message, 'webmaster@example.com', [user.email])

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
class ActivateView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_object_or_404(User, pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.activation_key = ''  # Opcjonalnie, usuń klucz aktywacyjny po aktywacji
            user.key_expires = None  # Opcjonalnie, usuń datę ważności
            user.save()
            return Response({'detail': 'Account activated successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Activation link is invalid.'}, status=status.HTTP_400_BAD_REQUEST)    
class PasswordResetView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        user = get_object_or_404(User, email=email)

        # Generowanie tokena resetowania hasła
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = (f'http://localhost:3000/reset-password/{uid}/{token}/')

        # Wysyłanie e-maila
        subject = 'Reset Your Password'
        message = render_to_string('password_reset_email.html', {
            'reset_link': reset_link,
        })
        send_mail(subject, message, 'webmaster@example.com', [email])

        return Response({'detail': 'Password reset link has been sent.'}, status=status.HTTP_200_OK)   
class ResetPasswordConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            new_password = request.data.get('new_password')
            user.set_password(new_password)
            user.save()
            return Response({'detail': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Reset link is invalid or expired.'}, status=status.HTTP_400_BAD_REQUEST) 
class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed("User not found!")
        if not user.check_password(password):
            raise AuthenticationFailed("Incorrect password!")
        if not user.is_active:
            raise AuthenticationFailed("Account is inactive!")
        
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