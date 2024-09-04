from django.urls import path,include
from .views import RegisterView, LoginView,UserView, LogoutView, TaskDetail, TaskListCreate

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('user/', UserView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('tasks/', TaskListCreate.as_view()),
    path('tasks/<int:pk>', TaskDetail.as_view()),
]
