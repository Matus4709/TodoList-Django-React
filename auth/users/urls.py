from django.urls import path,include
from .views import RegisterView, LoginView,UserView, LogoutView, TaskDetail, TaskListCreate,ActivateView,PasswordResetView,ResetPasswordConfirmView

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('tasks/', TaskListCreate.as_view()),
    path('tasks/<int:pk>', TaskDetail.as_view()),
    path('register/', RegisterView.as_view(), name='register'),
    path('activate/<uidb64>/<token>/', ActivateView.as_view(), name='activate'),
    path('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('reset-password/<uidb64>/<token>/', ResetPasswordConfirmView.as_view(), name='reset_password_confirm'),
]
